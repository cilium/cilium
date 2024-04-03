include ../../../Makefile.defs

CLANG := clang
STRIP := llvm-objcopy
CFLAGS := -O2 -g -Wall -Werror -I -I/usr/include -I$(ROOT_DIR)/bpf -I$(ROOT_DIR)/bpf/include $(CFLAGS)

TESTDATA_DIR := $(ROOT_DIR)/pkg/bpf/testdata
UIDGID := $(shell stat -c '%u:%g' ${ROOT_DIR})

TARGETS := \
	unreachable-tailcall

.PHONY: docker build clean

.DEFAULT_GOAL: docker
docker: ## Build the testdata binaries using the cilium-builder Docker image.
	docker run --rm -u "$(UIDGID)" -v "$(ROOT_DIR):/cilium" $(CILIUM_BUILDER_IMAGE) make -C /cilium/pkg/bpf/testdata clean build

clean: ## Remove testdata artifacts.
	find "$(TESTDATA_DIR)" -name "*.o" -delete

## Build the testdata binaries using the host's toolchain.
build: $(addsuffix .o,$(TARGETS))

%.o: %.c
	$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@
	$(STRIP) -g $@
