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

set -x

LIB=$1
RUNDIR=$2

DEV="cilium-probe"
PROBE_DIR=$(mktemp -d)
FEATURE_FILE="$RUNDIR/globals/bpf_features.h"

function cleanup {
	if [ ! -z "$PROBE_DIR" ]; then
		rm -rf $PROBE_DIR
	fi

	ip link del $DEV 2> /dev/null
}

trap cleanup EXIT

ip link del $DEV 2> /dev/null
ip link add $DEV type dummy || exit 1

function probe_run()
{
	PROBE="${LIB}/probes/$1"
	OUT="$PROBE_DIR/${1}.o"
	FEATURE=$2
	tc qdisc del dev $DEV clsact 2> /dev/null

	PROBE_OPTS="-D__NR_CPUS__=$(nproc) -O2 -target bpf -I$DIR -I. -I$LIB/include"

	clang $PROBE_OPTS -c $PROBE -o $OUT &&
	tc qdisc add dev $DEV clsact &&
	tc filter add dev $DEV ingress bpf da obj $OUT sec probe &&
	echo "#define $FEATURE" >> $FEATURE_FILE
}

echo "#ifndef BPF_FEATURES_H_" > $FEATURE_FILE
echo "#define BPF_FEATURES_H_" >> $FEATURE_FILE

probe_run "skb_change_tail.c" "HAVE_SKB_CHANGE_TAIL"

echo "#endif" >> $FEATURE_FILE
