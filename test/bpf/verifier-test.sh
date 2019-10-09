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
ALL_TC_PROGS="bpf_hostdev_ingress bpf_ipsec bpf_lxc bpf_netdev bpf_network bpf_overlay"
TC_PROGS=${TC_PROGS:-$ALL_TC_PROGS}
ALL_CG_PROGS="bpf_sock sockops/bpf_sockops sockops/bpf_redir"
CG_PROGS=${CG_PROGS:-$ALL_CG_PROGS}
ALL_XDP_PROGS="bpf_xdp"
XDP_PROGS=${XDP_PROGS:-$ALL_XDP_PROGS}
IGNORED_PROGS="bpf_alignchecker"
ALL_PROGS="${IGNORED_PROGS} ${ALL_CG_PROGS} ${ALL_TC_PROGS} ${ALL_XDP_PROGS}"
VERBOSE=false

BPFFS=${BPFFS:-"/sys/fs/bpf"}
TC=${TC:-"tc"}
IPROUTE2=${IPROUTE2:-"ip"}

function clean_maps {
	for f in $BPFFS/tc/globals/test_*; do
		rm -f $f
	done
}

function cleanup {
	$IPROUTE2 link del ${DEV} 2>/dev/null || true
	clean_maps
}

function get_section {
	grep "__section(" $DIR/$1 | sed 's/__sec[^\"]*\"\([0-9A-Za-z_-]*\).*/\1/'
}

function load_prog {
	loader=$1
	args=$2
	name=$3

	echo "=> Loading ${name}..."
	if $VERBOSE; then
		# Redirect stderr to stdout to assist caller parsing
		${loader} $args verbose 2>&1
	else
		# Only run verbose mode if loading fails.
		${loader} $args 2>/dev/null \
		|| ${loader} $args verbose
	fi
}

function load_prog_dev {
	loader=$1
	mode=$2
	prog=$3
	for section in $(get_section ${prog}.c); do
		local args="dev ${DEV} ${mode} obj ${DIR}/${prog}.o sec $section"
		load_prog "$loader" "$args" "$prog.c:$section"
	done
}

function load_tc {
	for p in ${TC_PROGS}; do
		load_prog_dev "$TC filter replace" "ingress bpf da" ${p}
	done
}

function load_cg {
	for p in ${CG_PROGS}; do
		echo "=> Skipping ${DIR}/${p}.c."
	done
}

function load_xdp {
	if $IPROUTE2 link set help 2>&1 | grep -q xdpgeneric; then
		$IPROUTE2 link set dev ${DEV} xdpgeneric off
		for p in ${XDP_PROGS}; do
			load_prog_dev "$IPROUTE2 link set" "xdpgeneric" ${p}
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
	handle_args "$@"
	handle_developers

	trap cleanup EXIT
	if [ "$TC_PROGS" != "" ] || [ "$XDP_PROGS" != "" ]; then
		$IPROUTE2 link add ${DEV} type dummy
		$TC qdisc replace dev ${DEV} clsact
	fi

	load_tc
	load_cg
	load_xdp
}

main "$@"
