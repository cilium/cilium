include ../Makefile.defs

FLAGS := -Iinclude -I. -D__NR_CPUS__=$(shell nproc) -O2

CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option
LLC_FLAGS   := -march=bpf -mcpu=probe -filetype=obj

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o bpf_lb.o bpf_xdp.o
SCRIPTS = init.sh join_ep.sh run_probes.sh spawn_netns.sh
LIB := $(shell find ./ -name '*.h')

TARGET=cilium-map-migrate

CLANG  ?= clang
LLC    ?= llc
HOSTCC ?= gcc

ifeq ("$(PKG_BUILD)","")
all: $(BPF) $(TARGET)

%.o: %.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@)
	$(QUIET) ${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

check:
	@$(ECHO_CHECK) bpf/*.c
	$(QUIET) sparse -Wsparse-all ${FLAGS} *.c
	$(QUIET) $(CLANG) ${CLANG_FLAGS} --analyze *.c

LB_OPTIONS = \
	-DSKIP_DEBUG \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3 -DLB_L4

bpf_lb.o: bpf_lb.c $(LIB)
	$(QUIET) set -e; \
	$(foreach OPTS,$(LB_OPTIONS), \
		$(ECHO_CC) " [$(OPTS)]"; \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@); \
		${LLC} ${LLC_FLAGS} -o /dev/null $(patsubst %.o,%.ll,$@); )
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@)
	$(QUIET) ${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

LXC_OPTIONS = \
	 -DSKIP_DEBUG \
	 -DDROP_ALL \
	 -DHAVE_LPM_MAP_TYPE \
	 -DHAVE_LRU_MAP_TYPE

bpf_lxc.o: bpf_lxc.c $(LIB)
	$(QUIET) set -e; \
	$(foreach OPTS,$(LXC_OPTIONS), \
		$(ECHO_CC) " [$(OPTS)]"; \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@); \
		${LLC} ${LLC_FLAGS} -o /dev/null $(patsubst %.o,%.ll,$@); )
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@)
	$(QUIET) ${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)
else
all: $(TARGET)
endif

$(TARGET): $(TARGET).c
	@$(ECHO_CC)
	@# Due to gcc bug, -lelf needs to be at the end.
	$(QUIET) ${HOSTCC} -Wall -O2 -I include/ $@.c -lelf -o $@

install:
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	$(QUIET)rm -fr *.o
	$(QUIET)rm -f $(TARGET)
