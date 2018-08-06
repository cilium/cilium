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
EPID=$6

function bpf_preprocess()
{
	SRC=$1

	clang -E -O2 -target bpf -I$RUNDIR/globals -I$EPDIR		\
		-I$LIB/include -c $LIB/$SRC -o $EPDIR/$SRC
}

function bpf_compile()
{
	IN=$1
	OUT=$2
	TYPE=$3
	EXTRA_CFLAGS=$4

	clang -O2 -g -target bpf -emit-llvm $EXTRA_CFLAGS			\
	      -Wno-address-of-packed-member -Wno-unknown-warning-option	\
	      -I$RUNDIR/globals -I$EPDIR -I$LIB/include			\
	      -D__NR_CPUS__=$(nproc)					\
	      -c $LIB/$IN -o - |					\
	llc -march=bpf -mcpu=probe -mattr=dwarfris -filetype=$TYPE -o $EPDIR/$OUT
}

echo "Join EP id=$EPDIR ifname=$IFNAME"

# Only generate ASM output if debug is enabled.
if [[ "${DEBUG}" == "true" ]]; then
  echo "kernel version: " `uname -a`
  echo "clang version: " `clang --version`
  bpf_compile bpf_lxc.c bpf_lxc.asm asm -g
  bpf_preprocess bpf_lxc.c
fi

bpf_compile bpf_lxc.c bpf_lxc.o obj
tc qdisc replace dev $IFNAME clsact || true
cilium-map-migrate -s $EPDIR/bpf_lxc.o
set +e
tc filter replace dev $IFNAME ingress prio 1 handle 1 bpf da obj $EPDIR/bpf_lxc.o sec from-container
RETCODE=$?
set -e
cilium-map-migrate -e $EPDIR/bpf_lxc.o -r $RETCODE
exit $RETCODE
