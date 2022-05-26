# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs
include ../../Makefile.quiet

DOCKER_CTR_ROOT_DIR := /src
DOCKER_CTR := $(CONTAINER_ENGINE) container run --rm \
		--workdir $(DOCKER_CTR_ROOT_DIR)/test/bpf \
		--volume $(ROOT_DIR):$(DOCKER_CTR_ROOT_DIR) \
		--user "$(shell id -u):$(shell id -g)"
DOCKER_RUN := $(DOCKER_CTR) cilium/bpf-mock

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
ALL_TESTS := unit-test nat-test drop-notify-test
TARGETS := $(BPF_TARGETS) $(ALL_TESTS)

all: $(TARGETS) unit-tests

elf-demo.o: elf-demo.c
	@$(ECHO_CC)
	$(QUIET) $(CLANG) ${FLAGS_CLANG} ${BPF_CC_FLAGS} -c $< -o - | $(LLC) ${BPF_LLC_FLAGS} -o $@

%: %.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) $(CLANG) ${FLAGS_CLANG} ${FLAGS} -I../../bpf/ $< -o $@

mocks:
	$(QUIET)$(MAKE) -C $(ROOT_DIR)/bpf/mock generate_helper_headers
	$(QUIET)$(MAKE) -C $(ROOT_DIR)/bpf/mock mock_helpers

$(ROOT_DIR)/bpf/mock/mocks/mock_conntrack_stub.c: mocks $(LIB)
	$(QUIET)$(MAKE) -C $(ROOT_DIR)/bpf/mock mock_customized filename=conntrack_stub.h

nat-test: nat-test.c $(LIB) $(ROOT_DIR)/bpf/mock/mocks/mock_conntrack_stub.c
	@$(ECHO_CC)
	$(QUIET) $(DOCKER_RUN) $(CLANG) $(FLAGS) -I../../bpf/mock -I $../../bpf/ -I../../../CMock/src -I../../../CMock/vendor/unity/src -I../../../hashmap/include  $< ../../../CMock/vendor/unity/src/unity.c ../../../CMock/src/cmock.c ../../../hashmap/src/hashmap.c ../../bpf/mock/mocks/mock_helpers.c ../../bpf/mock/mocks/mock_helpers_skb.c ../../bpf/mock/mocks/mock_conntrack_stub.c -o $@

drop-notify-test: drop-notify-test.c $(LIB) mocks
	@$(ECHO_CC)
	$(QUIET) $(DOCKER_RUN) $(CLANG) $(FLAGS) -I../../bpf/mock -I $../../bpf/ -I../../../CMock/src -I../../../CMock/vendor/unity/src  $< ../../../CMock/vendor/unity/src/unity.c ../../../CMock/src/cmock.c ../../bpf/mock/mocks/mock_helpers.c ../../bpf/mock/mocks/mock_helpers_skb.c -o $@

unit-tests: $(ALL_TESTS)
	@$(ECHO_CHECK)
	for test in $^; do \
		$(ECHO_CHECK) $$test; \
		$(ROOT_DIR)/$(RELATIVE_DIR)/$$test; \
	done

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGETS)
	$(MAKE) -C $(ROOT_DIR)/bpf/mock clean
