include ../../../Makefile.defs

CLANG := clang
STRIP := llvm-objcopy
CFLAGS := -O2 -g -Wall -Werror -I -I/usr/include -I$(ROOT_DIR)/bpf -I$(ROOT_DIR)/bpf/include $(CFLAGS) -mcpu=v3

TESTDATA_DIR := $(ROOT_DIR)/pkg/bpf/testdata
UIDGID := $(shell stat -c '%u:%g' ${ROOT_DIR})

TARGETS := \
	reachability \
	unreachable-tailcall \
	upgrade-map \
	unused-map-pruning \
	unused-map-false-negative

.PHONY: docker build clean

.DEFAULT_GOAL: docker
docker: ## Build the testdata binaries using the cilium-builder Docker image.
	docker run --rm -u "$(UIDGID)" -v "$(ROOT_DIR):/cilium" -e V=$(V) \
		$(CILIUM_BUILDER_IMAGE) make -C /cilium/pkg/bpf/testdata clean build

clean: ## Remove testdata artifacts.
	@$(ECHO_CLEAN)
	$(QUIET)find "$(TESTDATA_DIR)" -name "*.o" -delete

## Build the testdata binaries using the host's toolchain.
build: $(addsuffix .o,$(TARGETS))

%.o: %.c
	@$(ECHO_CC) $@
	$(QUIET)$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@
	$(QUIET)$(STRIP) -g $@
