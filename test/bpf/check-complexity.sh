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
	    -e "s/\(section '2\/8'\)/\1 (tail_call NAT64)/" \
	    -e "s/\(section '2\/9'\)/\1 (tail_call NAT46)/" \
	    -e "s/\(section '2\/10'\)/\1 (tail_call IPV6_FROM_LXC)/" \
	    -e "s/\(section '2\/11'\)/\1 (tail_call IPV4_TO_LXC_POLICY_ONLY)/" \
	    -e "s/\(section '2\/12'\)/\1 (tail_call IPV6_TO_LXC_POLICY_ONLY)/" \
	    -e "s/\(section '2\/13'\)/\1 (tail_call IPV4_TO_ENDPOINT)/" \
	    -e "s/\(section '2\/14'\)/\1 (tail_call IPV6_TO_ENDPOINT)/"
}

if ! grep -q "CILIUM_CALL_SIZE.*13" "$BPFDIR/lib/common.h" ; then
	echo "This script is out of date compared to CILIUM_CALL_SIZE." 1>&2
	exit 1
fi

"$TESTDIR/verifier-test.sh" -v | get_insn_cnt | annotate_section_names
