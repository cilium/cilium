#!/bin/bash
#
# Copyright 2016-2017 Authors of Cilium
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

set -e

LIB=$1
RUNDIR=$2
EPDIR=$3
IFNAME=$4
DEBUG=$5

echo "Join EP id=$EPDIR ifname=$IFNAME"

# This directory was created by the daemon and contains the per container header file
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -O2 -target bpf -I$RUNDIR/globals -I$EPDIR -I$LIB/include -Wno-address-of-packed-member -Wno-unknown-warning-option"

# Only generate ASM output if debug is enabled.
if [[ "${DEBUG}" == "true" ]]; then
  echo "kernel version: " `uname -a`
  echo "clang version: " `clang --version`
  clang $CLANG_OPTS -c $LIB/bpf_lxc.c -S -o $EPDIR/bpf_lxc.asm
fi

clang $CLANG_OPTS -c $LIB/bpf_lxc.c -o $EPDIR/bpf_lxc.o

tc qdisc replace dev $IFNAME clsact || true
tc filter replace dev $IFNAME ingress prio 1 handle 1 bpf da obj $EPDIR/bpf_lxc.o sec from-container
