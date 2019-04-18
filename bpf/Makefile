include ../Makefile.defs

.PHONY: all subdirs $(SUBDIRS) check preprocess assembly install clean

SUBDIRS = sockops

BPF_SIMPLE = bpf_netdev.o bpf_overlay.o bpf_xdp.o bpf_ipsec.o bpf_network.o bpf_alignchecker.o bpf_hostdev_ingress.c
BPF = bpf_lxc.o bpf_lb.o bpf_sock.o $(BPF_SIMPLE)
SCRIPTS = init.sh join_ep.sh run_probes.sh spawn_netns.sh

TARGET=cilium-map-migrate

include ./Makefile.bpf

ifeq ("$(PKG_BUILD)","")
all: $(BPF) $(TARGET) $(SUBDIRS)

$(BPF_SIMPLE): %.o: %.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

# Hack to get make to replace : with a space
space :=
space += 

# The following option combinations are compile tested
LB_OPTIONS = \
	-DSKIP_DEBUG \
	-DENABLE_IPV4:-DLB_L3 \
	-DENABLE_IPV4:-DLB_L4 \
	-DENABLE_IPV4:-DLB_L3:-DLB_L4 \
	-DENABLE_IPV6:-DLB_L3 \
	-DENABLE_IPV6:-DLB_L4 \
	-DENABLE_IPV6:-DLB_L3:-DLB_L4 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L4 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4

# These options are intended to max out the BPF program complexity. it is load
# tested as well.
MAX_LB_OPTIONS = -DENABLE_IPV4 -DENABLE_IPV6 -DLB_L3 -DLB_L4

bpf_lb.ll: bpf_lb.c $(LIB)
	$(QUIET) set -e; \
	$(foreach OPTS,$(LB_OPTIONS), \
		$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
		${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
		${LLC} ${LLC_FLAGS} -o /dev/null $@; )
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_LB_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_lb.o: bpf_lb.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_sock.ll: bpf_sock.c $(LIB)
	$(QUIET) set -e; \
	$(foreach OPTS,$(LB_OPTIONS), \
		$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
		${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
		${LLC} ${LLC_FLAGS} -o /dev/null $@; )
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_LB_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_sock.o: bpf_sock.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

# The following option combinations are compile tested
LXC_OPTIONS = \
	 -DSKIP_DEBUG \
	 -DHAVE_LPM_MAP_TYPE \
	 -DHAVE_LRU_MAP_TYPE \
	 -DENABLE_IPV4 \
	 -DENABLE_IPV4:-DHAVE_LPM_MAP_TYPE \
	 -DENABLE_IPV4:-DHAVE_LPM_MAP_TYPE:-DHAVE_LRU_MAP_TYPE \
	 -DENABLE_IPV6 \
	 -DENABLE_IPV6:-DHAVE_LPM_MAP_TYPE \
	 -DENABLE_IPV6:-DHAVE_LPM_MAP_TYPE:-DHAVE_LRU_MAP_TYPE \
	 -DENABLE_IPV6:-DENABLE_IPV4 \
	 -DENABLE_IPV4:-DENABLE_IPV6:-DHAVE_LPM_MAP_TYPE:-DHAVE_LRU_MAP_TYPE \
	 -DENABLE_HOST_REDIRECT:-DENABLE_IPV4:-DENABLE_IPV6 \
	 -DENABLE_HOST_REDIRECT:-DENABLE_IPV4:-DENABLE_IPV6:-DENABLE_NAT46

# These options are intended to max out the BPF program complexity. it is load
# tested as well.
MAX_LXC_OPTIONS = -DENABLE_IPV4 -DENABLE_IPV6

bpf_lxc.ll: bpf_lxc.c $(LIB)
	$(QUIET) set -e; \
	$(foreach OPTS,$(LXC_OPTIONS), \
		$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
		${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
		${LLC} ${LLC_FLAGS} -o /dev/null $@; )
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_LXC_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_lxc.o: bpf_lxc.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

subdirs: $(SUBDIRS)
$(SUBDIRS):
	@$(MAKE) -C $@
else
all: $(TARGET)
endif

$(TARGET): $(TARGET).c
	@$(ECHO_CC)
	@# Due to gcc bug, -lelf needs to be at the end.
	$(QUIET) ${HOSTCC} -Wall -O2 -Wno-format-truncation -I include/ $@.c -lelf -o $@

install:
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -fr *.o *.ll *.i *.s
	$(QUIET)rm -f $(TARGET)
