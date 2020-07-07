#!/bin/bash
#
# Copyright 2020 Authors of Cilium
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

set -eo pipefail

SCRIPTDIR="$(dirname $(realpath $0))"
BPFDIR=$(realpath $SCRIPTDIR/../../bpf/)


# object file with the dummy constants so that constchecker can test itself
XOBJ_SELF=bpf_constchecker_self.o
# object file with cilium constants
XOBJ=bpf_constchecker.o

# ensure that objects are up-to-date
make -C $BPFDIR $XOBJ_SELF $XOBJ

# NB: in both cases, we pass proper flags to go test, so that it only executes
# the constchecker tests
 CILIUM_CONSTCHECKER_BPF_OBJ=$BPFDIR/bpf_constchecker_self.o \
	 go test github.com/cilium/cilium/pkg/constchecker -run '^Test$' -check.f 'ConstSuite.*'
 CILIUM_CONSTCHECKER_BPF_OBJ=$BPFDIR/bpf_constchecker.o \
	 go test github.com/cilium/cilium/pkg/loadbalancer -run '^Test$' -check.f 'ConstSuite.*'
