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
set -e
set -u

LIB=$1
RUNDIR=$2

PROBE_DIR=$(mktemp -d)
FEATURE_FILE="$RUNDIR/globals/bpf_features.h"
INFO_FILE="$RUNDIR/bpf_features.log"
WARNING_FILE="$RUNDIR/bpf_requirements.log"

function cleanup {
	if [ ! -z "$PROBE_DIR" ]; then
		rm -rf "$PROBE_DIR"
	fi
}

trap cleanup EXIT

function probe_kernel_config()
{
    # BPF Kernel params verifier.
    local KCONFIG=""
    local RESULT=0
    # Coreos kernel config is on /proc/config (module configs).
    # Other distros in /boot/config-*
    local config_locations=("/proc/config" "/proc/config.gz"
        "/boot/config-$(uname -r)")
    local REQ_PARAMS=(
        "CONFIG_BPF=y" "CONFIG_BPF_SYSCALL=y" "CONFIG_NET_SCH_INGRESS=[m|y]"
        "CONFIG_NET_CLS_BPF=[m|y]" "CONFIG_NET_CLS_ACT=y" "CONFIG_BPF_JIT=y"
        "CONFIG_HAVE_EBPF_JIT=y")
    local OPT_PARAMS=(
        "CONFIG_CGROUP_BPF=y" "CONFIG_LWTUNNEL_BPF=y" "CONFIG_BPF_EVENTS=y")

    for config in "${config_locations[@]}"
    do
        if [[ -f "$config" ]]; then
            KCONFIG=$config
            break
        fi
    done

    if [[ -z "$KCONFIG" ]]; then
        echo "BPF/probes: Kernel config not found." >> $INFO_FILE
        return
    fi

    for key in "${OPT_PARAMS[@]}"
    do
        zgrep -E "${key}" $KCONFIG > /dev/null || {
            echo "BPF/probes: ${key} is not in kernel configuration" >> $INFO_FILE
            }
    done

    for key in "${REQ_PARAMS[@]}"
    do
        zgrep -E "${key}" $KCONFIG > /dev/null || {
            RESULT=1;
            echo "BPF/probes: ${key} is not in kernel configuration" >> $WARNING_FILE
            }
    done

    if [[ "$RESULT" -gt 0 ]]; then
        echo "BPF/probes: Missing kernel configuration" >> $WARNING_FILE
    fi
}


# High level probes that require to invoke tc.
function probe_run_tc()
{
	PROBE="${LIB}/probes/$1"
	OUT="$PROBE_DIR/${1}.o"
	FEATURE=$2
	tc qdisc del dev $DEV clsact 2> /dev/null

	PROBE_OPTS="-D__NR_CPUS__=$(nproc) -O2 -target bpf -I$DIR -I. -I$LIB/include -Wall -Wno-address-of-packed-member -Wno-unknown-warning-option"

	clang $PROBE_OPTS -c "$PROBE" -o "$OUT" &&
	tc qdisc add dev $DEV clsact &&
	tc filter add dev $DEV ingress bpf da obj $OUT sec probe &&
	echo "#define $FEATURE" >> "$FEATURE_FILE"
}

# Low level probes that only check verifier.
function probe_run_ll()
{
	PROBE_BASE="${LIB}/probes"
	OUT="$PROBE_DIR"
	LIB_INCLUDE="${LIB}/include"
	PROBE_OPTS="-O2 -I$OUT -I$PROBE_BASE -I$LIB_INCLUDE -Wall"

	for PROBE in "${PROBE_BASE}"/*.t
	do
		OUT_BIN=`basename "$PROBE"`

		cp "$PROBE" "$OUT/raw_probe.t"
		clang $PROBE_OPTS "$PROBE_BASE/raw_main.c" -o "$OUT/$OUT_BIN" &&
		"$OUT/$OUT_BIN" 1>> "$FEATURE_FILE" 2>> "$INFO_FILE"
	done
}

for file in $INFO_FILE $WARNING_FILE
do
	rm -f "$file"
done

echo "#ifndef BPF_FEATURES_H_"  > "$FEATURE_FILE"
echo "#define BPF_FEATURES_H_" >> "$FEATURE_FILE"
echo "" >> "$FEATURE_FILE"

#probe_run_tc "skb_change_tail.c" "HAVE_SKB_CHANGE_TAIL"
probe_kernel_config
probe_run_ll

echo "#endif /* BPF_FEATURES_H_ */" >> "$FEATURE_FILE"

for file in $INFO_FILE $WARNING_FILE
do
	if [ ! -s "$file" ]; then
		rm -f "$file"
	fi
done
