include ../Makefile.defs

CLANG_FLAGS := -I.

BPF = lxc_bpf.c bpf_netdev.c bpf_overlay.c
MAP_CTRL = map_ctrl
SCRIPTS = init.sh join_ep.sh leave_ep.sh
LIB := $(shell find ./lib -name '*.h')

all: $(MAP_CTRL) nop.o $(BPF)

nop.o:
	clang -O2 -emit-llvm -c nop.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

lxc_bpf.o:
	clang -O2 -emit-llvm -c lxc_bpf.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

bpf_netdev.o:
	clang -O2 -emit-llvm -c bpf_netdev.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

bpf_overlay.o:
	clang -O2 -emit-llvm -c bpf_overlay.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

$(MAP_CTRL): map_ctrl.o libbpf.o

clean:
	rm -f $(MAP_CTRL)
	rm -fr *.o

tests:

install:
	$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/ $(BPF)
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ $(MAP_CTRL)
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ $(SCRIPTS)
	$(INSTALL) -m 0644 -t $(DESTDIR)$(LIBDIR)/cilium/lib/ $(LIB)
