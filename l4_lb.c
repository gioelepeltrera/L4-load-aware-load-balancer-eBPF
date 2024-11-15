// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"
#include "l4_lb.h"

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

static const char *const usages[] = {
    "l4_lb [options] [[--] args]",
    "l4_lb [options]",
    NULL,
};

int update_min(struct l4_lb_bpf *skel, int be_count) {
    int ret = EXIT_SUCCESS;

    // Log all backends
    int backends_fd = bpf_map__fd(skel->maps.xdp_backeneds);
    int resources_fd = bpf_map__fd(skel->maps.xdp_resources);
    int status_fd = bpf_map__fd(skel->maps.xdp_be_status);

    if (backends_fd < 0 || resources_fd < 0 || status_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    __u32 min_ip_id = 0;
    in_addr_t ip = 0;
    struct status_t min_status = {0};
    int print_every = 1000;
    while (1) {


    // Initial lookup
    if (bpf_map_lookup_elem(backends_fd, &min_ip_id, &ip)) {
        log_error("Failed to lookup BPF map of the min: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    
    if (bpf_map_lookup_elem(status_fd, &ip, &min_status)) {
        log_error("Failed to lookup status for initial min: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    float min = 0;
    if(min_status.packets == 0){
        min = 0;
    }else{
        min = (float)min_status.packets / min_status.flow_count;
    }
    if(print_every == 0){
        log_info("--------------------min: %f, id: %d-------------------------", min, min_ip_id);
        for(int i = 0;i<be_count;i++){
            struct status_t status = {0};
            in_addr_t current_ip = 0;
            if (bpf_map_lookup_elem(backends_fd, &i, &current_ip)) {
                log_error("Failed to lookup BPF map for backend %d: %s", i, strerror(errno));
                return EXIT_FAILURE;
            }
            if (bpf_map_lookup_elem(status_fd, &current_ip, &status)) {
                log_error("Failed to lookup status for backend %d: %s", i, strerror(errno));
                return EXIT_FAILURE;
            }
            log_info("Backend %d: %x - packets: %ld, flow_count: %ld, load: %f", i, current_ip, status.packets, status.flow_count, (float)status.packets/status.flow_count);
        }
        print_every = 1000;
    }
    for (__u32 i = 0; i < be_count; i++) {
        struct status_t status = {0};
        in_addr_t current_ip = 0;

        if (bpf_map_lookup_elem(backends_fd, &i, &current_ip)) {
            log_error("Failed to lookup BPF map for backend %d: %s", i, strerror(errno));
            return EXIT_FAILURE;
        }

        if (bpf_map_lookup_elem(status_fd, &current_ip, &status)) {
            log_error("Failed to lookup status for backend %d: %s", i, strerror(errno));
            return EXIT_FAILURE;
        }


        float current_load =0;
        if(status.packets !=0){

         current_load =(float)status.packets / status.flow_count;
        }

        //log_info("Backend %d: %x - packets: %ld, flow_count: %ld, load: %f", i, current_ip, status.packets, status.flow_count, current_load);

        if (current_load < min) {
            min_ip_id = i;
            min = current_load;
            ip = current_ip;

            __u32 min_index = 2;
            if (bpf_map_update_elem(resources_fd, &min_index, &ip, BPF_ANY)) {
                log_error("Failed to update BPF min map: %s", strerror(errno));
                return EXIT_FAILURE;
            }

        }
    }
        unsigned int mSeconds = 1000;
        usleep(mSeconds);
        //sleep(1);
        print_every = print_every -1;
    }

    return ret;
}

int load_maps_config(const char *config_file, struct l4_lb_bpf *skel) {
    struct root *root;
    cyaml_err_t erry;
    int ret = EXIT_SUCCESS;

    erry = cyaml_load_file(config_file, &config, &root_schema, (void **) &root, NULL);
    if (erry != CYAML_OK) {
        fprintf(stderr, "ERROR: %s\n", cyaml_strerror(erry));
        return EXIT_FAILURE;
    }
    log_info("Loaded VIP: %s", root->vip);
    //log all backends
    int err = 0;
    int backends_fd = bpf_map__fd(skel->maps.xdp_backeneds);
    int resources_fd = bpf_map__fd(skel->maps.xdp_resources);
    int status_fd = bpf_map__fd(skel->maps.xdp_be_status);
    if (backends_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        return ret;
    }
    if (resources_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        return ret;
    }
    if (status_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        return ret;
    }
    struct in_addr addr;
    for (int i = 0; i < root->backends_count; i++) {
        log_info("Backend %d: %s", i, root->backends[i].ip);

        // Convert the IP to an integer
        int ret = inet_pton(AF_INET, root->backends[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", root->backends[i].ip);
            ret = EXIT_FAILURE;
            return ret;
        }

        err = bpf_map_update_elem(backends_fd, &i, &addr.s_addr, BPF_ANY);
        if (err) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            return ret;
        }
        struct status_t status = {0};
        struct status_t status2 = {0};
        status.packets = 0;
        status.flow_count = 1;
        err = bpf_map_update_elem(status_fd, &addr.s_addr, &status, BPF_ANY);
        err  = bpf_map_lookup_elem(status_fd, &addr.s_addr, &status2);
        log_info("status: IP: %x: -%ld, %ld", addr.s_addr, status2.packets, status2.flow_count);
        if (err) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            return ret;
        }
    }
    int key = 0;

    ret = inet_pton(AF_INET, root->vip, &addr);
    if (ret != 1) {
        log_error("Failed to convert IP %s to integer", root->vip);
        ret = EXIT_FAILURE;
        return ret;
    }
    
    err = bpf_map_update_elem(resources_fd, &key , &addr.s_addr, BPF_ANY);
    if (err) {
        log_error("Failed to update BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        return ret;
    }
    key = 1;
    err = bpf_map_update_elem(resources_fd, &key, &root->backends_count, BPF_ANY); 
    if (err) {
        log_error("Failed to update BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        return ret;
    }
    key = 2;
    if(&root->backends_count > 0){

        ret = inet_pton(AF_INET, root->backends[0].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", root->backends[0].ip);
            ret = EXIT_FAILURE;
            return ret;
        }
        err = bpf_map_update_elem(resources_fd, &key, &addr.s_addr, BPF_ANY);
        if (err) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            return ret;
        }
        __u32 min = 0;
        err = bpf_map_lookup_elem(resources_fd, &key, &min);
        if (err) {
            log_error("Failed to lookup BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            return ret;
        }
        log_info("min: %x", min);
    }


    cyaml_free(&config, &root_schema, root, 0);

    return root->backends_count;

}

int main(int argc, const char **argv) {

    cyaml_err_t err;
    struct l4_lb_bpf *skel = NULL;

    const char *config_file = NULL;
    const char *iface = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('c', "config", &config_file, "Path to the YAML configuration file", NULL, 0, 0),
        OPT_STRING('i', "iface", &iface, "Interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse,
                      "\nThis program is a simple load balancer that forwards packets"
                      " to one of the backends specified in the configuration file. "
                      "\nThe program attaches to the interface specified in the input parameter",
                      "\nThe '-i' argument is used to specify the "
                      "interface where to attach the program");
    argc = argparse_parse(&argparse, argc, argv);

    if (config_file == NULL) {
        log_warn("Use default configuration file: %s", "config.yaml");
        config_file = "config.yaml";
    }

    
    if (iface == NULL) {
        log_warn("Use default interface: %s", "veth1");
        iface = "veth1";
    }

    
    skel = l4_lb_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }
    bpf_program__set_type(skel->progs.l4_lb, BPF_PROG_TYPE_XDP);
    if (l4_lb_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }
    int be_count = 0;
    be_count = load_maps_config(config_file, skel);


    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;
    int ifindex = if_nametoindex(iface);   
    log_info("Attaching program to interface %s (ifindex: %d)", iface, ifindex);
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);
    if (err) {
        log_fatal("Error while attaching BPF programs");
        goto cleanup;
    }
    log_info("Successfully attached!");
    update_min(skel, be_count);
    sleep(10000);


cleanup:
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    l4_lb_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}