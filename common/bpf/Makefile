CLANG_FLAGS := -I.

all: map_ctrl nop.o lxc_bpf.o bpf_netdev.o bpf_overlay.o

nop.o:
	clang -O2 -emit-llvm -c nop.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

lxc_bpf.o:
	clang -O2 -emit-llvm -c lxc_bpf.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

bpf_netdev.o:
	clang -O2 -emit-llvm -c bpf_netdev.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

bpf_overlay.o:
	clang -O2 -emit-llvm -c bpf_overlay.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

map_ctrl: map_ctrl.o libbpf.o

clean:
	rm -f map_ctrl
	rm -fr *.o
