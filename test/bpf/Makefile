include ../../Makefile.defs

FLAGS := -I../../bpf/include -I. -D__NR_CPUS__=$(shell nproc) -O2
BPF_CC_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
BPF_LLC_FLAGS   := -march=bpf -mcpu=probe -filetype=obj

CLANG ?= clang
LLC ?= llc

all: perf-event-test bpf-event-test.o

perf-event-test: perf-event-test.go
	$(GO) build -i $(GOBUILD) -o $@ $<

bpf-event-test.o: bpf-event-test.c
	$(CLANG) ${BPF_CC_FLAGS} -c $< -o - | $(LLC) ${BPF_LLC_FLAGS} -o $@

clean:
	rm -f bpf-event-test.o perf-event-test
