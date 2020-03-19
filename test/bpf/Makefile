include ../../Makefile.defs

FLAGS := -I../../bpf/ -I../../bpf/include -I. -D__NR_CPUS__=$(shell nproc) -O2
BPF_CC_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
BPF_LLC_FLAGS := -march=bpf -mcpu=probe -filetype=obj

LIB := $(shell find ../../bpf/ -name '*.h')

CLANG ?= $(QUIET) clang
LLC ?= llc

BPF_TARGETS := elf-demo.o
TARGETS := $(BPF_TARGETS) unit-test
all: $(TARGETS)

elf-demo.o: elf-demo.c
	@$(ECHO_CC)
	$(CLANG) ${BPF_CC_FLAGS} -c $< -o - | $(LLC) ${BPF_LLC_FLAGS} -o $@

%: %.c $(LIB)
	@$(ECHO_CC)
	$(CLANG) $(FLAGS) -I../../bpf/ $< -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGETS)
