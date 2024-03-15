include ../../../Makefile.defs

.PHONY: build

CILIUM_BUILDER_IMAGE=$(shell cat $(ROOT_DIR)/images/cilium/Dockerfile | grep "ARG CILIUM_BUILDER_IMAGE=" | cut -d"=" -f2)

##@ Default
build:
	docker run --rm -v $(ROOT_DIR):/cilium $(CILIUM_BUILDER_IMAGE) clang -target bpf -Wall -O2 -g -I -I/usr/include -I/cilium/bpf -I/cilium/bpf/include -c /cilium/pkg/bpf/testdata/unreachable-tailcall.c -o /cilium/pkg/bpf/testdata/unreachable-tailcall.o
