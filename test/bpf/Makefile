include ../../Makefile.defs

all: perf-event-test bpf-event-test.o

perf-event-test: perf-event-test.go
	$(GO) build -i $(GOBUILD) -o $@ $<

bpf-event-test.o: bpf-event-test.c
	clang -I../../bpf/include -O2 -emit-llvm -D__NR_CPUS__=$(shell nproc) -c $< -o - | llc -march=bpf -filetype=obj -o $@

clean:
	rm -f bpf-event-test.o perf-event-test
