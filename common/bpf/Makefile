CLANG_FLAGS := -DNODE_ID=1 -DDEBUG

all: map_ctrl nop.o lxc_bpf.o

nop.o:
	clang -O2 -emit-llvm -c nop.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

lxc_bpf.o:
	clang -O2 -emit-llvm -c lxc_bpf.c ${CLANG_FLAGS} -o - | llc -march=bpf -filetype=obj -o $@

map_ctrl: map_ctrl.o libbpf.o

clean:
	rm -f map_ctrl
	rm -fr *.o

