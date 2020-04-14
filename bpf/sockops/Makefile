# Copyright 2017-2020 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include ../../Makefile.defs

.PHONY: all assembly check preprocess clean

BPF = bpf_sockops.o bpf_redir.o

include ../Makefile.bpf

SOCKOPS_OPTIONS = \
	 -DSKIP_DEBUG \
	 -DHAVE_LPM_TRIE_MAP_TYPE \
	 -DHAVE_LRU_HASH_MAP_TYPE \
	 -DENABLE_IPV4 \
	 -DENABLE_IPV6

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
