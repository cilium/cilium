include ../Makefile.defs

CLANG_FLAGS := -Iinclude -D__NR_CPUS__=$(shell nproc) -O2 -target bpf -I.

# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o bpf_lb.o
SCRIPTS = init.sh join_ep.sh run_probes.sh
LIB := $(shell find ./lib -name '*.h')

ifeq ("$(PKG_BUILD)","")

all: $(BPF)

%.o: %.c
	clang ${CLANG_FLAGS} -c $< -o $@

LB_OPTIONS = \
	 \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3 -DLB_L4

bpf_lb.o:
	$(foreach OPTS,$(LB_OPTIONS), \
		clang ${OPTS} ${CLANG_FLAGS} -c bpf_lb.c -o $@;)

else

all:

endif

clean:
	rm -fr *.o
