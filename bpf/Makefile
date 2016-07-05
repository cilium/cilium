include ../Makefile.defs

CLANG_FLAGS := -Iinclude -D__NR_CPUS__=$(shell nproc) -O2 -target bpf -I. -Wall -Werror

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o
SCRIPTS = init.sh join_ep.sh leave_ep.sh
LIB := $(shell find ./lib -name '*.h')

all: $(BPF)
	$(MAKE) -C go

bpf_lxc.o:
	clang ${CLANG_FLAGS} -c bpf_lxc.c -o $@

bpf_netdev.o:
	clang ${CLANG_FLAGS} -c bpf_netdev.c -o $@

bpf_overlay.o:
	clang ${CLANG_FLAGS} -c bpf_overlay.c -o $@

clean:
	rm -fr *.o
	$(MAKE) -C go clean

tests:
	$(MAKE) -C go tests

runtime-tests:
	$(MAKE) -C go runtime-tests

install:
	$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/ $(BPF:.o=.c)
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ $(SCRIPTS)
	$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/lib/ $(LIB)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/include/
	cp -r include/* $(DESTDIR)$(LIBDIR)/cilium/include/
	$(MAKE) -C go install
