include ../../../Makefile.defs

CLANG := clang
CFLAGS := -O2 -g -Wall -Werror -I -I/usr/include -I$(ROOT_DIR)/bpf -I$(ROOT_DIR)/bpf/include $(CFLAGS) -mcpu=v3

TESTDATA_DIR := $(ROOT_DIR)/tools/stackwhere/testdata
UIDGID := $(shell stat -c '%u:%g' ${ROOT_DIR})

TARGETS := \
	stacktest

.PHONY: docker build clean

.DEFAULT_GOAL: docker
docker: ## Build the testdata binaries using the cilium-builder Docker image.
	docker run --rm -u "$(UIDGID)" -v "$(ROOT_DIR):/cilium" $(CILIUM_BUILDER_IMAGE) make -C /cilium/tools/stackwhere/testdata clean build

clean: ## Remove testdata artifacts.
	find "$(TESTDATA_DIR)" -name "*.o" -delete

## Build the testdata binaries using the host's toolchain.
build: $(addsuffix .o,$(TARGETS))

%.o: %.c
	$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@
