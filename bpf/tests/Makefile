# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

include ../../Makefile.defs

MAKEFLAGS += -r

CLANG ?= clang
LLC   ?= llc

FLAGS := -I$(ROOT_DIR)/bpf/include -I$(ROOT_DIR)/bpf -D__NR_CPUS__=$(shell nproc --all) -O2 -g

CLANG_FLAGS := ${FLAGS} -target bpf -std=gnu99 -nostdinc -emit-llvm
# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Wextra -Werror -Wshadow
CLANG_FLAGS += -Wno-address-of-packed-member
CLANG_FLAGS += -Wno-unknown-warning-option
CLANG_FLAGS += -Wno-gnu-variable-sized-type-not-at-end
CLANG_FLAGS += -Wimplicit-int-conversion -Wenum-conversion
LLC_FLAGS := -march=bpf
# Mimics the mcpu values set by cilium-agent. See GetBPFCPU().
ifeq ("$(KERNEL)","netnext")
LLC_FLAGS += -mcpu=v3
else
LLC_FLAGS += -mcpu=v2
endif

.PHONY: all clean

TEST_OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c)) $(patsubst %c, %i, $(wildcard *.c))

%.o: %.ll $(LIB)
	$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $<

%.ll: %.c
	$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

%.i: %.c
	$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -E -c $< -o $@

all: $(TEST_OBJECTS)

clean:
	rm -f $(wildcard *.ll)
	rm -f $(wildcard *.o)
	rm -f $(wildcard *.i)
