include ../Makefile.defs

CLANG_FLAGS := -Iinclude -D__NR_CPUS__=$(shell nproc) -O2 -target bpf -I.

# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o bpf_lb.o
SCRIPTS = init.sh join_ep.sh run_probes.sh
LIB := $(shell find ./lib -name '*.h')

CLANG ?= clang

ifeq ("$(PKG_BUILD)","")

all: $(BPF)

%.o: %.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

SPACE :=
SPACE +=

LB_OPTIONS = \
	-DUNKNOWN \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3:-DLB_L4 \
	-DLB_L3:-DLB_L4:-DLB_REDIRECT \
	-DLB_L3:-DLB_L4:-DENCAP_IFINDEX

bpf_lb.o:
	$(foreach OPTS,$(LB_OPTIONS), \
		${CLANG} $(subst :,$(SPACE),$(OPTS)) ${CLANG_FLAGS} -c bpf_lb.c -o /dev/null;)

LXC_OPTIONS = \
	 -DUNKNOWN \
	 -DDROP_ALL

bpf_lxc.o:
	$(foreach OPTS,$(LXC_OPTIONS), \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c bpf_lxc.c -o /dev/null;)

else

all:

endif

install:

clean:
	rm -fr *.o
