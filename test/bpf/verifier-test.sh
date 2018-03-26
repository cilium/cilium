#!/bin/bash
#
# Copyright 2018 Authors of Cilium
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

DEV="cilium-probe"
DIR=$(dirname $0)/../../bpf
TC_PROGS="bpf_lb bpf_lxc bpf_netdev bpf_overlay"

function clean_maps {
	rm -rf /sys/fs/bpf/tc/globals/*
}

function cleanup {
	ip link del ${DEV} 2>/dev/null || true
	clean_maps
}

function get_section {
	grep "__section(" $1 | sed 's/__sec[^\"]*\"\([0-9A-Za-z_-]*\).*/\1/'
}

function load_prog {
	loader=$1
	mode=$2
	prog=$3
	for section in $(get_section ${prog}.c); do
		echo "=> Loading ${prog}.c:${section}..."
		${loader} dev ${DEV} ${mode} obj ${prog}.o sec $section 2>/dev/null \
			|| ${loader} dev ${DEV} ${mode} obj ${prog}.o \
			   sec $section verbose
	done
}

if [ $(id -u) -ne 0 ]; then
	echo "Must be run as root"
	exit 1
fi

if ps cax | grep cilium-agent; then
	echo "WARNING: This test will conflict with running cilium instances." 2>&1
	echo "Shut down cilium before continuing."
	exit 1
fi

trap cleanup EXIT
ip link add ${DEV} type dummy
tc qdisc replace dev ${DEV} clsact

for p in ${TC_PROGS}; do
	load_prog "tc filter replace" "ingress bpf da" ${DIR}/${p}
	clean_maps
done
if ip link set help 2>&1 | grep -q xdpgeneric; then
	ip link set dev ${DEV} xdpgeneric off
	load_prog "ip link set" "xdpgeneric" ${DIR}/bpf_xdp
else
	echo "=> Skipping ${DIR}/bpf_xdp.c."
	echo "Ensure you have linux >= 4.12 and recent iproute2 to test XDP."
fi
