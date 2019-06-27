#!/bin/bash
#
# Copyright 2018-2019 Authors of Cilium
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

DEV="cilium-probe"
DIR=$(dirname $0)/../../bpf
TC_PROGS="bpf_hostdev_ingress bpf_ipsec bpf_lb bpf_lxc bpf_netdev bpf_network bpf_overlay"
CG_PROGS="bpf_sock sockops/bpf_sockops sockops/bpf_redir"
XDP_PROGS="bpf_xdp"
IGNORED_PROGS="bpf_alignchecker"
ALL_PROGS="${IGNORED_PROGS} ${CG_PROGS} ${TC_PROGS} ${XDP_PROGS}"
VERBOSE=false

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
		if $VERBOSE; then
			# Redirect stderr to stdout to assist caller parsing
			${loader} dev ${DEV} ${mode} obj ${prog}.o \
				  sec $section verbose 2>&1
		else
			# Only run verbose mode if loading fails.
			${loader} dev ${DEV} ${mode} obj ${prog}.o sec $section 2>/dev/null \
			|| ${loader} dev ${DEV} ${mode} obj ${prog}.o sec $section verbose
		fi
	done
}

function load_tc {
	for p in ${TC_PROGS}; do
		load_prog "tc filter replace" "ingress bpf da" ${DIR}/${p}
		clean_maps
	done
}

function load_cg {
	for p in ${CG_PROGS}; do
		echo "=> Skipping ${DIR}/${p}.c."
	done
}

function load_xdp {
	if ip link set help 2>&1 | grep -q xdpgeneric; then
		ip link set dev ${DEV} xdpgeneric off
		for p in ${XDP_PROGS}; do
			load_prog "ip link set" "xdpgeneric" ${DIR}/${p}
			clean_maps
		done
	else
		echo "=> Skipping ${DIR}/bpf_xdp.c."
		echo "Ensure you have linux >= 4.12 and recent iproute2 to test XDP." 1>&2
	fi
}

function handle_args {
	if [ $(id -u) -ne 0 ]; then
		echo "Must be run as root" 1>&2
		exit 1
	fi

	if ps cax | grep cilium-agent; then
		echo "WARNING: This test will conflict with running cilium instances." 1>&2
		echo "Shut down cilium before continuing." 1>&2
		exit 1
	fi

	# If first argument is "-v", always set verbose
	if [ $# -gt 0 ]; then
		case "$1" in
		-v|--verbose)
			VERBOSE=true
			;;
		*)
			echo "Unrecognized argument '$1'" 1>&2
			exit 1
			;;
		esac
	fi
}

function handle_developers {
	set +e
	PROG_DIFF=$(diff -u \
		<(find ${DIR}/ -name "bpf*.c" | sed 's/^.*bpf\/\([^.]*\).*$/\1/' | sort) \
		<(for p in ${ALL_PROGS}; do echo $p; done | sort))
	PROGS_NOT_COVERED=$?
	set -e
	if [ $PROGS_NOT_COVERED -ne 0 ]; then
		echo "This script doesn't verify all BPF programs:" 1>&2
		echo "${PROG_DIFF}" | tail -n +4 1>&2
		exit 1
	fi
}

function main {
	handle_args
	handle_developers

	trap cleanup EXIT
	ip link add ${DEV} type dummy
	tc qdisc replace dev ${DEV} clsact

	load_tc
	load_cg
	load_xdp
}

main "$@"
