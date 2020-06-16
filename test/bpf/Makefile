# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

FLAGS := -I../../bpf/ -I../../bpf/include -I. -D__NR_CPUS__=$(shell nproc --all) -O2
FLAGS_CLANG := -Wall -Wextra -Werror -Wshadow -Wno-unused-parameter
FLAGS_CLANG += -Wno-address-of-packed-member
FLAGS_CLANG += -Wno-unknown-warning-option
FLAGS_CLANG += -Wno-gnu-variable-sized-type-not-at-end
FLAGS_CLANG += -Wdeclaration-after-statement

BPF_CC_FLAGS := ${FLAGS} -target bpf -std=gnu89 -nostdinc -emit-llvm
BPF_LLC_FLAGS := -march=bpf -mcpu=probe -filetype=obj

LIB := $(shell find ../../bpf/ -name '*.h')

CLANG ?= $(QUIET) clang
LLC ?= llc

BPF_TARGETS := elf-demo.o
TARGETS := $(BPF_TARGETS) unit-test
all: $(TARGETS)

elf-demo.o: elf-demo.c
	@$(ECHO_CC)
	$(CLANG) ${FLAGS_CLANG} ${BPF_CC_FLAGS} -c $< -o - | $(LLC) ${BPF_LLC_FLAGS} -o $@

%: %.c $(LIB)
	@$(ECHO_CC)
	$(CLANG) ${FLAGS_CLANG} ${FLAGS} -I../../bpf/ $< -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGETS)
