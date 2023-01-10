# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

include ../../Makefile.defs

.PHONY: all clean

BPF = bpf_sockops.o bpf_redir.o

include ../Makefile.bpf

SOCKOPS_OPTIONS = \
	 -DSKIP_DEBUG \
	 -DHAVE_LPM_TRIE_MAP_TYPE \
	 -DHAVE_LRU_HASH_MAP_TYPE \
	 -DENABLE_IPV4 \
	 -DENABLE_IPV6 \
	 -DENCAP_IFINDEX=1

all: $(BPF)

%.ll: %.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} ${SOCKOPS_OPTIONS} -c $< -o $@

$(BPF): %.o: %.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -fr *.o *.ll *.i
