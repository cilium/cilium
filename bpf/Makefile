include ../Makefile.defs

FLAGS := -Iinclude -I. -D__NR_CPUS__=$(shell nproc) -O2

CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option
LLC_FLAGS   := -march=bpf -mcpu=probe -filetype=obj

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o bpf_lb.o bpf_xdp.o
SCRIPTS = init.sh join_ep.sh run_probes.sh
LIB := $(shell find ./lib -name '*.h')

CLANG ?= clang
LLC   ?= llc

ifeq ("$(PKG_BUILD)","")

all: $(BPF)

clean-tags:
	-rm -f cscope.out cscope.in.out cscope.po.out tags

tags: *.c $(LIB)
	cscope -R -b -q
	ctags -R .

%.o: %.c
	${CLANG} ${CLANG_FLAGS} -c $< -o - | ${LLC} ${LLC_FLAGS} -o $@

check:
	sparse -Wsparse-all ${FLAGS} *.c
	clang ${CLANG_FLAGS} --analyze *.c

LB_OPTIONS = \
	-DUNKNOWN \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3 -DLB_L4

bpf_lb.o:
	$(foreach OPTS,$(LB_OPTIONS), \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c bpf_lb.c -o - | ${LLC} ${LLC_FLAGS} -o /dev/null;)

LXC_OPTIONS = \
	 -DUNKNOWN \
	 -DDROP_ALL

bpf_lxc.o:
	$(foreach OPTS,$(LXC_OPTIONS), \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c bpf_lxc.c -o - | ${LLC} ${LLC_FLAGS} -o /dev/null;)

else

all:

endif

install:

clean: clean-tags
	rm -fr *.o
