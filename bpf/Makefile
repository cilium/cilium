include ../Makefile.defs

CLANG_FLAGS := -I. -Wall -Werror

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o
SCRIPTS = init.sh join_ep.sh leave_ep.sh
LIB := $(shell find ./lib -name '*.h')

all: nop.o $(BPF)
	$(MAKE) -C go

nop.o:
	clang -O2 -target bpf -c nop.c ${CLANG_FLAGS} -o $@

bpf_lxc.o:
	clang -O2 -target bpf -c bpf_lxc.c ${CLANG_FLAGS} -o $@

bpf_netdev.o:
	clang -O2 -target bpf -c bpf_netdev.c ${CLANG_FLAGS} -o $@

bpf_overlay.o:
	clang -O2 -target bpf -c bpf_overlay.c ${CLANG_FLAGS} -o $@

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
	$(MAKE) -C go install
