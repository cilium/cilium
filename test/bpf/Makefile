# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs
include ../../Makefile.quiet

FLAGS := -I../../bpf/ -I../../bpf/include -I. -D__NR_CPUS__=$(shell nproc --all) -O2 -Werror
FLAGS_CLANG := -Wall -Wextra -Werror -Wshadow -Wno-unused-parameter
FLAGS_CLANG += -Wno-address-of-packed-member
FLAGS_CLANG += -Wno-unknown-warning-option
FLAGS_CLANG += -Wno-gnu-variable-sized-type-not-at-end
FLAGS_CLANG += -Wdeclaration-after-statement
FLAGS_CLANG += -g

BPF_CC_FLAGS := ${FLAGS} -target bpf -std=gnu89 -nostdinc -emit-llvm
BPF_LLC_FLAGS := -march=bpf -mcpu=probe -filetype=obj

LIB := $(shell find ../../bpf/ -name '*.h')

CLANG ?= clang
LLC ?= llc

BPF_TARGETS := elf-demo.o
ALL_TESTS := unit-test
TARGETS := $(BPF_TARGETS) $(ALL_TESTS)

all: $(TARGETS) unit-tests

elf-demo.o: elf-demo.c
	@$(ECHO_CC)
	$(QUIET) $(CLANG) ${FLAGS_CLANG} ${BPF_CC_FLAGS} -c $< -o - | $(LLC) ${BPF_LLC_FLAGS} -o $@

%: %.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) $(CLANG) ${FLAGS_CLANG} ${FLAGS} -I../../bpf/ $< -o $@

unit-tests: $(ALL_TESTS)
	@$(ECHO_CHECK)
	for test in $^; do \
		$(ECHO_CHECK) $$test; \
		$(ROOT_DIR)/$(RELATIVE_DIR)/$$test; \
	done

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGETS)
