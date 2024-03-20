# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

include ../../Makefile.defs

MAKEFLAGS += -r

CLANG ?= clang
LLC   ?= llc

FLAGS := -I$(ROOT_DIR)/bpf/include -I$(ROOT_DIR)/bpf -D__NR_CPUS__=$(shell nproc --all) -O2 -g

CLANG_FLAGS := ${FLAGS} --target=bpf -std=gnu99 -nostdinc -emit-llvm
# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Wextra -Werror -Wshadow
CLANG_FLAGS += -Wno-address-of-packed-member
CLANG_FLAGS += -Wno-unknown-warning-option
CLANG_FLAGS += -Wno-gnu-variable-sized-type-not-at-end
CLANG_FLAGS += -Wimplicit-int-conversion -Wenum-conversion
CLANG_FLAGS += -Wimplicit-fallthrough
# Create dependency files for each .o file.
CLANG_FLAGS += -MD
LLC_FLAGS := -march=bpf
# Mimics the mcpu values set by cilium-agent. See GetBPFCPU().
ifneq (,$(filter $(KERNEL),510 61 netnext))
LLC_FLAGS += -mcpu=v3
else
LLC_FLAGS += -mcpu=v2
endif

.PHONY: all clean run

TEST_OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

%.o: %.ll %.i $(LIB)
	@$(ECHO_CC)
	@# Remove the .o file to force recompilation, only rely on make's caching, not clangs
	rm -f $@
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $<

%.ll: %.c
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

%.i: %.c
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -E -c $< -o $@

all: $(TEST_OBJECTS)

clean:
	rm -f $(wildcard *.ll)
	rm -f $(wildcard *.o)
	rm -f $(wildcard *.i)
	rm -f $(wildcard *.d)

BPF_TEST_FLAGS:=
ifneq ($(shell id -u), 0)
		BPF_TEST_FLAGS += -exec "sudo -E"
endif
ifeq ($(V),1)
    BPF_TEST_FLAGS += -test.v
endif
ifeq ($(COVER),1)
	ifndef COVERFORMAT
		COVERFORMAT:=html
	endif
    BPF_TEST_FLAGS += -coverage-report $(ROOT_DIR)/bpf-coverage.$(COVERFORMAT) -coverage-format $(COVERFORMAT)
ifdef NOCOVER
    BPF_TEST_FLAGS += -no-test-coverage "$(NOCOVER)"
endif
endif
ifeq ($(INSTRLOG),1)
    BPF_TEST_FLAGS += -instrumentation-log $(ROOT_DIR)/test/bpf-instrumentation.log
endif
ifdef RUN
    BPF_TEST_FLAGS += -run $(RUN)
endif
ifdef DUMPCTX
    BPF_TEST_FLAGS += -dump-ctx
endif

run:
	$(QUIET)$(GO) test ./bpftest -bpf-test-path $(ROOT_DIR)/bpf/tests $(BPF_TEST_FLAGS)

-include $(TEST_OBJECTS:.o=.d)
