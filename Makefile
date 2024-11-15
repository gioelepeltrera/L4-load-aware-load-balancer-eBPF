# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
SHELL := /bin/bash
PKG_CONFIG := pkg-config
LIBBPF_SRC := $(abspath ../libs/libbpf/src)
BPFTOOL_SRC := $(abspath ../libs/bpftool/src)
LIBARGPARSE_SRC := $(abspath ../libs/libargparse)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_PKGCONFIG := $(abspath $(OUTPUT)/pkgconfig)
LIBARGPARSE_OBJ := $(abspath ../libs/libargparse/libargparse.a)
LIBLOG_OBJ := $(abspath $(OUTPUT)/liblog.o)
LIBLOG_SRC := $(abspath ../libs/liblog/src/log.c)
LIBLOG_HDR := $(abspath ../libs/liblog/src/)
LIBCYAML_SRC := $(abspath ../libs/libcyaml)
LIBCYAML_OBJ := $(abspath $(OUTPUT)/libcyaml.a)
LIBCYAML_DST := $(abspath $(OUTPUT))
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
# INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(OUTPUT)/libxdp/include -I$(LIBARGPARSE_SRC) -I$(dir $(VMLINUX))
INCLUDES := -I$(OUTPUT) -I../../libs/libbpf/include/uapi -I$(LIBARGPARSE_SRC) -I$(LIBLOG_HDR)
CFLAGS := -g -Wall -DLOG_USE_COLOR
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) 

APPS = l4_lb xdp_loader

HHDV2_CONFIG_DEPS = libnl-3.0
HHDV2_PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(HHDV2_CONFIG_DEPS))
HHDV2_PKG_LIBS := $(shell $(PKG_CONFIG) --static --libs $(HHDV2_CONFIG_DEPS))

INCLUDES += $(HHDV2_PKG_CFLAGS)
ALL_LDFLAGS += -lrt -ldl -lpthread -lm $(LIBCYAML_OBJ) -lyaml $(HHDV2_PKG_LIBS)

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

clean-app:
	$(call msg,CLEAN-APP)
	$(Q)rm -rf $(APPS)
	$(Q)rm -rf $(OUTPUT)/*.skel.h
	$(Q)rm -rf $(OUTPUT)/*.o

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build libargparse
$(LIBARGPARSE_OBJ):
	$(call msg,LIBARGPARSE,$@)
	$(Q)$(MAKE) -C $(LIBARGPARSE_SRC)

# Build liblog
$(LIBLOG_OBJ):
	$(call msg,LIBLOG,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(LIBLOG_SRC) -o $@

# Build libcyaml
$(LIBCYAML_OBJ):
	$(call msg,LIBCYAML,$@)
	$(Q)$(MAKE) clean -C $(LIBCYAML_SRC)
	$(Q)$(MAKE) install -C $(LIBCYAML_SRC) PREFIX=$(LIBCYAML_DST) \
										   LIBDIR= \
	                                       INCLUDEDIR= \
	                                       VARIANT=release

# Build BPF code
$(OUTPUT)/%.bpf.o: ebpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard ebpf/%.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(LIBCYAML_OBJ) $(OUTPUT)/%.o $(LIBBPF_OBJ) $(LIBCYAML_OBJ) $(LIBARGPARSE_OBJ) $(LIBLOG_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

format:
	clang-format -style=file -i *.c *.h
	clang-format -style=file -i ebpf/*.c ebpf/*.h
	@grep -n "TODO" *.[ch] || true

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: