include ../Makefile.defs

CLANG_FLAGS := -Iinclude -D__NR_CPUS__=$(shell nproc) -O2 -target bpf -I. -Wall -Werror

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o bpf_lb.o
SCRIPTS = init.sh join_ep.sh leave_ep.sh run_probes.sh
LIB := $(shell find ./lib -name '*.h')

ifeq ("$(PKG_BUILD)","")

all: $(BPF)
	$(MAKE) -C go

bpf_lxc.o:
	clang ${CLANG_FLAGS} -c bpf_lxc.c -o $@

bpf_netdev.o:
	clang ${CLANG_FLAGS} -c bpf_netdev.c -o $@

bpf_overlay.o:
	clang ${CLANG_FLAGS} -c bpf_overlay.c -o $@

LB_OPTIONS = \
	 \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3 -DLB_L4

bpf_lb.o:
	$(foreach OPTS,$(LB_OPTIONS), \
		clang ${OPTS} ${CLANG_FLAGS} -c bpf_lb.c -o $@;)

install: install-common
	$(MAKE) -C go install

else

all:

install: install-common

endif

install-common:
	$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/ $(BPF:.o=.c)
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ $(SCRIPTS)
	$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/lib/ $(LIB)
	for dir in `find include probes -type d`; do \
		$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/$$dir; \
		for f in `find $$dir -maxdepth 1 -type f`; do \
			$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/$$dir $$f; \
		done; \
	done

clean:
	rm -fr *.o
	$(MAKE) -C go clean
