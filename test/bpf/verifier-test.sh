#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eo pipefail

DEV="cilium-probe"
DIR=$(dirname $0)/../../bpf
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
FORCE=false
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
		${loader} $args verbose 2>&1 || $FORCE
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

	if $BPFTOOL help 2>&1 | grep -q feature; then
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
}


function load_cg {
	cg_prog_type_init

	mkdir -p ${TESTMOUNT}
	for p in ${CG_PROGS}; do
		ELF_SECTIONS="$(readelf -S $DIR/${p}.o)"
		for section in $(get_section ${p}.c); do
			if [ "${prog_types[$section]}" == "" ]; then
				echo "=> Skipping ${p}.c:$section"
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
		-f|--force)
			FORCE=true
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
