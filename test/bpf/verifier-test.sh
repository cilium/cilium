#!/bin/bash
#
# Copyright 2018-2021 Authors of Cilium
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
MAPTOOL=$(dirname $0)/../../tools/maptool/maptool
# all known bpf programs (object files).
# ALL_PROGS will be tested again source files to find non-tested bpf code
ALL_TC_PROGS="bpf_lxc bpf_host bpf_network bpf_overlay"
ALL_CG_PROGS="bpf_sock sockops/bpf_sockops sockops/bpf_redir"
ALL_XDP_PROGS="bpf_xdp"
IGNORED_PROGS="bpf_alignchecker tests/bpf_ct_tests custom/bpf_custom"
ALL_PROGS="${IGNORED_PROGS} ${ALL_CG_PROGS} ${ALL_TC_PROGS} ${ALL_XDP_PROGS}"

# if {TC,CG,XDP}_PROGS is set (even if empty) use the existing value.
# Otherwise, use ALL_{TC,CG,XDP}
if [[ ! -v TC_PROGS ]]; then
    TC_PROGS=$ALL_TC_PROGS
fi
if [[ ! -v CG_PROGS ]]; then
    CG_PROGS=$ALL_CG_PROGS
fi
if [[ ! -v XDP_PROGS ]]; then
    XDP_PROGS=$ALL_XDP_PROGS
fi

VERBOSE=false
RUN_ALL_TESTS=false

BPFFS=${BPFFS:-"/sys/fs/bpf"}
TESTMOUNT=$BPFFS/test
BPFTOOL=${BPFTOOL:-"bpftool"}
TC=${TC:-"tc"}
IPROUTE2=${IPROUTE2:-"ip"}

FEATURES=""

# The following arrays are used for loading cgroups programs, and are
# initialized in cg_prog_type_init().
#
# prog_types is keyed by a section in a bpf/*{,/*}.c source file, with
# the value as the TC prog_type argument.
declare -A prog_types
# attach_types is keyed by a section in a bpf/*{,/*}.c source file,
# with the value as the tc or bpftool attach_type argument.
declare -A attach_types

function clean_maps {
	for f in $BPFFS/tc/globals/test_*; do
		rm -f $f
	done
}

function cleanup {
	$IPROUTE2 link del ${DEV} 2>/dev/null || true
	clean_maps
	rm -rf ${TESTMOUNT}
}

function get_section {
	sed -n 's/.*__section("\([0-9A-Za-z_-]*\).*/\1/p' $DIR/$1
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

# $1 - Partial macro to check
function check_macro {
	# $FEATURES here is deliberately unquoted to ensure the correct
	# grepping behaviour, otherwise we get issues with exit code 141
	$RUN_ALL_TESTS || echo $FEATURES | grep -q " HAVE_[^ ]*$1"
}

function cg_prog_type_init {
	FEATURES="$($BPFTOOL feature probe macros)"

	mkdir -p ${TESTMOUNT}

	# These show up in sockops progs; skip them quietly.
	prog_types["int"]="SKIP"
	prog_types["_version"]="SKIP"
	prog_types["version"]="SKIP"
	if $BPFTOOL help 2>&1 | grep -q feature; then
		if check_macro SOCK_OPS; then
			prog_types["sockops"]="sock_ops"
			attach_types["sockops"]="sock_ops"
		fi
		if check_macro SK_MSG; then
			prog_types["sk_msg"]="sock_ops"
			attach_types["sk_msg"]="msg_verdict"
		fi
		if check_macro CGROUP_INET4_CONNECT; then
			prog_types["from-sock4"]="sockaddr"
			attach_types["from-sock4"]="connect4"
		fi
		if check_macro CGROUP_INET6_CONNECT; then
			prog_types["from-sock6"]="sockaddr"
			attach_types["from-sock6"]="connect6"
		fi
		if check_macro UDP4_RECVMSG; then
			prog_types["snd-sock4"]="sockaddr"
			prog_types["rcv-sock4"]="sockaddr"
			attach_types["snd-sock4"]="sendmsg4"
			attach_types["rcv-sock4"]="recvmsg4"
		fi
		if check_macro UDP6_RECVMSG; then
			prog_types["snd-sock6"]="sockaddr"
			prog_types["rcv-sock6"]="sockaddr"
			attach_types["snd-sock6"]="sendmsg6"
			attach_types["rcv-sock6"]="recvmsg6"
		fi
	fi

	# Hack: Get the eppolicymap and sockmap pinned
	#
	# Basically none of the loaders support arbitrarily creating a map
	# of type 'hash_of_maps' right now, so we have a little tool in the
	# repo that allows creation of this map type from the commandline.
	#
	# Only set it up if we determined kernel support above!
	if [ "${#attach_types[@]}" -gt 1 ]; then
		$MAPTOOL eppolicymap "test_cilium_ep_to_policy" 2>/dev/null
		$MAPTOOL sockmap "test_sock_ops_map" 2>/dev/null
	fi
}

function load_sock_prog {
	prog=$1
	pinpath=$2
	prog_type=$3
	attach_type=$4
	section=$5

	local args="pin $pinpath obj ${prog}.o type $prog_type \
		    attach_type $attach_type sec $section"
	if $VERBOSE; then
		$TC exec bpf $args verbose 2>&1
	else
		$TC exec bpf $args 2>/dev/null \
		|| $TC exec bpf $args verbose
	fi
}

function load_sockops_prog {
	prog="$1"
	pinpath="$2"

	# cilium_signals is omitted from this list, because the sockops progs
	# don't support BPF_MAP_TYPE_PERF_EVENT_ARRAY for now.
	ALL_MAPS="cilium_ipcache cilium_ep_to_policy cilium_lxc sock_ops_map	\
		cilium_metrics cilium_tunnel_map cilium_encrypt_state		\
		cilium_lb6_reverse_nat cilium_lb6_services cilium_lb6_backends	\
		cilium_lb4_reverse_nat cilium_lb4_services cilium_lb4_backends	\
		cilium_events"

	map_args=""
	for map in $ALL_MAPS; do
		map_args="$map_args map name test_$map pinned /sys/fs/bpf/tc/globals/test_$map"
	done

	echo "=> Loading ${p}.c:${section}..."
	if $VERBOSE; then
		$BPFTOOL -m prog load "$prog.o" "$pinpath" $map_args 2>&1
	else
		$BPFTOOL -m prog load "$prog.o" "$pinpath" $map_args 2>/dev/null \
		|| $BPFTOOL -m prog load "$prog.o" "$pinpath" $map_args
	fi
}

function load_cg {
	cg_prog_type_init

	mkdir -p $TESTMOUNT/sockops
	for p in ${CG_PROGS}; do
		ELF_SECTIONS="$(readelf -S $DIR/${p}.o)"
		for section in $(get_section ${p}.c); do
			if [ "${prog_types[$section]}" == "" ]; then
				echo "=> Skipping ${p}.c:$section"
				continue
			elif [ "${prog_types[$section]}" == "SKIP" ]; then
				continue
			elif ! echo $ELF_SECTIONS | grep -q $section; then
				echo "=> Skipping ${p}.c:$section (not found in ELF)"
				continue
			fi

			local prog_type=${prog_types[$section]}
			local attach_type=${attach_types[$section]}
			if [ "$prog_type" = "sockaddr" ]; then
				local args="exec bpf pin $TESTMOUNT/$p obj $DIR/${p}.o \
					type $prog_type \
					attach_type $attach_type sec $section"
				load_prog "$TC" "$args" "${p}.o:$section"
			else
				load_sockops_prog "$DIR/$p" "$TESTMOUNT/$p"
			fi
			rm -f $TESTMOUNT/$p
		done
	done
}

function load_xdp {
	# The verifier compares the type of the BPF program that created each
	# pinned map to the type of the new program that is trying to use those
	# maps. It errors if the two types (original map creator vs. map user)
	# don't match.
	# Since previous loaded programs are of TC type, we need to remove all maps
	# before creating them again from XDP programs.
	clean_maps

	if $IPROUTE2 link set dev ${DEV} xdpgeneric off 2>/dev/null; then
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
	while [ $# -gt 0 ]; do
		key="$1"

		case "$key" in
		-a|--all)
			echo "Running all tests even if support detection fails" 1>&2
			RUN_ALL_TESTS=true
			shift;;
		-v|--verbose)
			VERBOSE=true
			shift;;
		*)
			echo "Unrecognized argument '$1'" 1>&2
			exit 1
			;;
		esac
	done
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

	if [ -n "$TC_PROGS" ]; then
		load_tc
	fi
	if [ -n "$CG_PROGS" ]; then
		load_cg
	fi
	if [ -n "$XDP_PROGS" ]; then
		load_xdp
	fi
}

main "$@"
