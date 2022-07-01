#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eo pipefail

TESTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
BPFDIR="$TESTDIR/../../bpf/"

function get_insn_cnt {
	grep -e "^Prog" -e processed -e "Proccessed" -e "^=>" -e "over limit"
}

# These are derived from bpf/lib/common.h CILIUM_CALL_*.
function annotate_section_names {
	sed -e "s/\(section \)'\(1\)\/\([0-9x]*\)'/\1'\2\/\3' (lxc ingress program for EP \3)/" \
	    -e "s/\(section '2\/1'\)/\1 (tail_call DROP_NOTIFY)/" \
	    -e "s/\(section '2\/2'\)/\1 (tail_call ERROR_NOTIFY)/" \
	    -e "s/\(section '2\/3'\)/\1 (tail_call SEND_ICMP6_ECHO_REPLY)/" \
	    -e "s/\(section '2\/4'\)/\1 (tail_call HANDLE_ICMP6_NS)/" \
	    -e "s/\(section '2\/5'\)/\1 (tail_call SEND_ICMP6_TIME_EXCEEDED)/" \
	    -e "s/\(section '2\/6'\)/\1 (tail_call ARP)/" \
	    -e "s/\(section '2\/7'\)/\1 (tail_call IPV4_FROM_LXC)/" \
	    -e "s/\(section '2\/10'\)/\1 (tail_call IPV6_FROM_LXC)/" \
	    -e "s/\(section '2\/11'\)/\1 (tail_call IPV4_TO_LXC_POLICY_ONLY)/" \
	    -e "s/\(section '2\/12'\)/\1 (tail_call IPV6_TO_LXC_POLICY_ONLY)/" \
	    -e "s/\(section '2\/13'\)/\1 (tail_call IPV4_TO_ENDPOINT)/" \
	    -e "s/\(section '2\/14'\)/\1 (tail_call IPV6_TO_ENDPOINT)/" \
	    -e "s/\(section '2\/15'\)/\1 (tail_call IPV4_NODEPORT_NAT)/" \
	    -e "s/\(section '2\/16'\)/\1 (tail_call IPV6_NODEPORT_NAT)/" \
	    -e "s/\(section '2\/17'\)/\1 (tail_call IPV4_NODEPORT_REVNAT)/" \
	    -e "s/\(section '2\/18'\)/\1 (tail_call IPV6_NODEPORT_REVNAT)/" \
	    -e "s/\(section '2\/19'\)/\1 (tail_call IPV4_ENCAP_NODEPORT_NAT)/" \
	    -e "s/\(section '2\/20'\)/\1 (tail_call IPV4_NODEPORT_DSR)/" \
	    -e "s/\(section '2\/21'\)/\1 (tail_call IPV6_NODEPORT_DSR)/" \
	    -e "s/\(section '2\/22'\)/\1 (tail_call IPV4_FROM_HOST)/" \
	    -e "s/\(section '2\/23'\)/\1 (tail_call IPV6_FROM_HOST)/" \
	    -e "s/\(section '2\/24'\)/\1 (tail_call IPV6_ENCAP_NODEPORT_NAT)/" \
	    -e "s/\(section '2\/25'\)/\1 (tail_call IPV4_FROM_LXC_CONT)/" \
	    -e "s/\(section '2\/26'\)/\1 (tail_call IPV6_FROM_LXC_CONT)/" \
	    -e "s/\(section '2\/27'\)/\1 (tail_call IPV4_CT_INGRESS)/" \
	    -e "s/\(section '2\/28'\)/\1 (tail_call IPV4_CT_INGRESS_POLICY_ONLY)/" \
	    -e "s/\(section '2\/29'\)/\1 (tail_call IPV4_CT_EGRESS)/" \
	    -e "s/\(section '2\/30'\)/\1 (tail_call IPV6_CT_INGRESS)/" \
	    -e "s/\(section '2\/31'\)/\1 (tail_call IPV6_CT_INGRESS_POLICY_ONLY)/" \
	    -e "s/\(section '2\/32'\)/\1 (tail_call IPV6_CT_EGRESS)/"
}

if ! grep -q "CILIUM_CALL_SIZE.*33" "$BPFDIR/lib/common.h" ; then
	echo "This script is out of date compared to CILIUM_CALL_SIZE." 1>&2
	exit 1
fi

"$TESTDIR/verifier-test.sh" -v -f | get_insn_cnt | annotate_section_names
