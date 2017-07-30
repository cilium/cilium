include ../Makefile.defs

FLAGS := -Iinclude -I. -D__NR_CPUS__=$(shell nproc) -O2
CLANG_FLAGS :=  ${FLAGS} -target bpf

# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o
SCRIPTS = init.sh join_ep.sh run_probes.sh
LIB := $(shell find ./lib -name '*.h')

CLANG ?= clang

ifeq ("$(PKG_BUILD)","")

all: $(BPF)

%.o: %.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

check:
	sparse -Wsparse-all ${FLAGS} *.c
	clang ${CLANG_FLAGS} --analyze *.c

LB_OPTIONS = \
	-DUNKNOWN \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3 -DLB_L4

bpf_netdev.o:
	$(foreach OPTS,$(LB_OPTIONS), \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c bpf_netdev.c -o /dev/null;)

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
