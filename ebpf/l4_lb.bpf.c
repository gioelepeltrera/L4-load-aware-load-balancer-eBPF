#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>


struct flow_t {
   __u32 IPsrc;
   __u32 IPdst;
   __u16 srcPort;
   __u16 dstPort;
   __u8  protocol;

};

struct status_t {
    __u64 packets;
    __u64 flow_count;
    // float load;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_t);
    __type(value, __u32);
    __uint(max_entries, 1024*1024);
} xdp_link_user_be SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct status_t);
    __uint(max_entries, 64);
} xdp_be_status SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xdp_backeneds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 3);
} xdp_resources SEC(".maps");


static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
   struct iphdr *ip = (struct iphdr *)(data + *nh_off);
   int hdr_size = sizeof(*ip);

   /* Byte-count bounds check; check if current pointer + size of header
    * is after data_end.
    */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   hdr_size = ip->ihl * 4;
   if (hdr_size < sizeof(*ip))
      return -1;

   /* Variable-length IPv4 header, need to use byte-based arithmetic */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *iphdr = ip;

   return ip->protocol;
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr) {
   struct udphdr *udp = data + *nh_off;
   int hdr_size = sizeof(*udp);

   if ((void *)udp + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *udphdr = udp;

   int len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
   if (len < 0)
      return -1;

   return len;
}

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum) {
  int i;
#pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__)) static inline void
ipv4_csum(void* data_start, int data_size, __u64* csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void ipv4_csum_inline(
    void* iph,
    __u64* csum) {
  __u16* next_iph_u16 = (__u16*)iph;
#pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}


static __always_inline int add_ip_header(struct xdp_md *ctx, __u32 dest_ip)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip_hdr;
    struct iphdr *ip_hdr_orig;
    struct ethhdr eth_cpy;
    __u16 nf_off = 0;

    if ((void *)eth + sizeof(struct ethhdr) > data_end)
        return -1;

    /* First copy the original Ethernet header */
    __builtin_memcpy(&eth_cpy, eth, sizeof(struct ethhdr));
    
    int err = parse_ethhdr(data, data_end, &nf_off, &eth);
    if (err < 0) {
        return -1;
    }
    err = parse_iphdr(data, data_end, &nf_off, &ip_hdr);
    if (err < 0) {
        return -1;
    }
    unsigned long hdr_size = ip_hdr->ihl * 4;
    /* Then add space in front of the packet */
    if (bpf_xdp_adjust_head(ctx, 0 - hdr_size))
        return -1;

    /* Need to re-evaluate data_end and data after head adjustment, and
    * bounds check, even though we know there is enough space (as we
    * increased it).
    */
    data_end = (void *)(long)ctx->data_end;
    eth = (void *)(long)ctx->data;

    if ((void *)eth + sizeof(struct ethhdr) > data_end)
        return -1;

    /* Copy back Ethernet header in the right place, populate VLAN tag with
    * ID and proto, and set outer Ethernet header to VLAN type.
    */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
    unsigned char temp_addr[ETH_ALEN];
    __builtin_memcpy(temp_addr, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, temp_addr, ETH_ALEN);

    ip_hdr = (void *)eth + sizeof(struct ethhdr);

    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end)
        return -1;
    
    ip_hdr_orig = (void *)eth + sizeof(struct ethhdr) + hdr_size;

    if((void *)ip_hdr_orig + sizeof(struct iphdr) > data_end){
        return -1;
    }
    

    // copy all the fields of iphdr from ip_hdr_orig to ip_hdr
    ip_hdr->addrs = ip_hdr_orig->addrs;
    ip_hdr->check = ip_hdr_orig->check;
    ip_hdr->daddr = ip_hdr_orig->daddr;
    ip_hdr->frag_off = ip_hdr_orig->frag_off;
    ip_hdr->id = ip_hdr_orig->id;
    ip_hdr->ihl = ip_hdr_orig->ihl;
    ip_hdr->protocol = ip_hdr_orig->protocol;
    ip_hdr->saddr = ip_hdr_orig->saddr;
    ip_hdr->tos = ip_hdr_orig->tos;
    ip_hdr->tot_len = bpf_htons(bpf_ntohs(ip_hdr_orig->tot_len)+hdr_size);
    ip_hdr->ttl = ip_hdr_orig->ttl;
    ip_hdr->version = ip_hdr_orig->version;

    bpf_printk("DEST IP: %x", dest_ip);
    ip_hdr->daddr = dest_ip;
    ip_hdr->protocol = IPPROTO_IPIP;
    //////ip_hdr->protocol = 0x04;

    __u64 csum = -1;
    ipv4_csum_inline(ip_hdr, &csum);
    ip_hdr->check = csum;
    bpf_printk("Added ip header check : %d", ip_hdr->check);

    return 0;
}


SEC("xdp")
int l4_lb(struct xdp_md *ctx) {
    bpf_printk("\n\t\t__NEW PACKET RECEIVED__");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u16 nf_off = 0;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udphdr;
    int udp_len;
    int err;

    int eth_type, ip_type;
    int action = XDP_PASS;
    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);
    if (eth_type == bpf_ntohs(ETH_P_ARP)) {
      action = XDP_DROP;
      bpf_printk("Packet is ARP");
      return action;
    }
    if (eth_type != bpf_htons(ETH_P_IP)) {
        bpf_printk("Packet is not an IPv4 packet %d", eth_type);
        return XDP_DROP;
    }
    ip_type = parse_iphdr(data, data_end, &nf_off, &ip);

    if (ip_type < 0) {
        bpf_printk("Packet is not a valid IPv4 packet");
        return XDP_DROP;
    }
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    
    int min = 0;
    __u32 *vip = bpf_map_lookup_elem(&xdp_resources, &min);
    if (!vip) {
        bpf_printk("Failed to find VIP");
        return XDP_DROP;
    }
    if (dst_ip != *vip) {
        bpf_printk("Packet not for VIP");
        return XDP_DROP;
    }
    if (ip->protocol == IPPROTO_UDP){
        udp_len = parse_udphdr(data, data_end, &nf_off, &udphdr);
        if (udp_len < 0) {
            bpf_printk("Failed to parse UDP header");
            return XDP_DROP;
        }
        __u16 src_port = bpf_ntohs(udphdr->source);
        __u16 dst_port = bpf_ntohs(udphdr->dest);
        bpf_printk("Flow from %x:%d to %x:%d", src_ip, src_port, dst_ip, dst_port);
        struct flow_t flow = {
            .IPsrc = src_ip,
            .IPdst = dst_ip,
            .srcPort = src_port,
            .dstPort = dst_port,
            .protocol = ip->protocol
        };
        __u32 *be = bpf_map_lookup_elem(&xdp_link_user_be, &flow);
        if (be) {
            bpf_printk("Found backend %x", *be);
            struct status_t *status = bpf_map_lookup_elem(&xdp_be_status, be);
            if (!status) {
                bpf_printk("Failed to find status");
                return XDP_DROP;
            }
            __sync_fetch_and_add(&status->packets, 1);
            
        }
        else {
            bpf_printk("Backend not found");
            // be = minval
            int min = 2;
            be = bpf_map_lookup_elem(&xdp_resources, &min);
            if (!be) {
                bpf_printk("Failed to find min backend ip");
                return XDP_DROP;
            }
            err = bpf_map_update_elem(&xdp_link_user_be, &flow, be, BPF_ANY);
            if(err){
                bpf_printk("Failed to update map");
                return XDP_DROP;
            }
            struct status_t *status = bpf_map_lookup_elem(&xdp_be_status, be);
            if (!status) {
                bpf_printk("Failed to find status");
                return XDP_DROP;
            }
            __sync_fetch_and_add(&status->packets, 1);
            __sync_fetch_and_add(&status->flow_count, 1);
            bpf_printk("Added flow to backend %x", be);
            
        }
        //add ip hdr in front of the other ip
        dst_ip = *be;
        if(add_ip_header(ctx, dst_ip) < 0){
            bpf_printk("Failed to add ip header");
            return XDP_DROP;
        }

        bpf_printk("Retransmitting packet...");
        return XDP_TX;
        
    }
    bpf_printk("Packet not UDP, dropping...");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";