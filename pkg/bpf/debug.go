//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package bpf

import (
	"fmt"

	"github.com/cilium/cilium/common"
)

const (
	DBG_CAPTURE_UNSPEC = iota
	DBG_CAPTURE_FROM_LXC
	DBG_CAPTURE_FROM_NETDEV
	DBG_CAPTURE_FROM_OVERLAY
	DBG_CAPTURE_DELIVERY
	DBG_CAPTURE_FROM_LB
	DBG_CAPTURE_AFTER_V46
	DBG_CAPTURE_AFTER_V64
)

const (
	DBG_UNSPEC = iota
	DBG_GENERIC
	DBG_LOCAL_DELIVERY
	DBG_ENCAP
	DBG_LXC_FOUND
	DBG_POLICY_DENIED
	DBG_CT_LOOKUP
	DBG_CT_MATCH
	DBG_CT_CREATED
	DBG_CT_CREATED2
	DBG_ICMP6_HANDLE
	DBG_ICMP6_REQUEST
	DBG_ICMP6_NS
	DBG_ICMP6_TIME_EXCEEDED
	DBG_CT_VERDICT
	DBG_DECAP
	DBG_PORT_MAP
	DBG_ERROR_RET
	DBG_TO_HOST
	DBG_TO_STACK
	DBG_PKT_HASH
	DBG_LB6_LOOKUP_MASTER
	DBG_LB6_LOOKUP_MASTER_FAIL
	DBG_LB6_LOOKUP_SLAVE
	DBG_LB6_LOOKUP_SLAVE_SUCCESS
	DBG_LB6_REVERSE_NAT_LOOKUP
	DBG_LB6_REVERSE_NAT
	DBG_LB4_LOOKUP_MASTER
	DBG_LB4_LOOKUP_MASTER_FAIL
	DBG_LB4_LOOKUP_SLAVE
	DBG_LB4_LOOKUP_SLAVE_SUCCESS
	DBG_LB4_REVERSE_NAT_LOOKUP
	DBG_LB4_REVERSE_NAT
)

// must be in sync with <bpf/lib/conntrack.h>
const (
	CT_NEW int = iota
	CT_ESTABLISHED
	CT_REPLY
	CT_RELATED
)

var ctState = map[int]string{
	CT_NEW:         "New",
	CT_ESTABLISHED: "Established",
	CT_REPLY:       "Reply",
	CT_RELATED:     "Related",
}

func CtState(state int32) string {
	txt, ok := ctState[int(state)]
	if ok {
		return txt
	}

	return DropReason(uint8(state))
}

func CtInfo(arg1 uint32, arg2 uint32) string {
	return fmt.Sprintf("sport=%d dport=%d nexthdr=%d flags=%d",
		arg1>>16, arg1&0xFFFF, arg2>>8, arg2&0xFF)
}

type DebugMsg struct {
	Type    uint8
	SubType uint8
	Source  uint16
	Hash    uint32
	Arg1    uint32
	Arg2    uint32
}

func (n *DebugMsg) Dump(data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d DEBUG: ", prefix, n.Hash, n.Source)
	switch n.SubType {
	case DBG_GENERIC:
		fmt.Printf("No message, arg1=%d (%#x) arg2=%d (%#x)\n", n.Arg1, n.Arg1, n.Arg2, n.Arg2)
	case DBG_LOCAL_DELIVERY:
		fmt.Printf("Attempting local delivery for container id %d from seclabel %d\n", n.Arg1, n.Arg2)
	case DBG_ENCAP:
		fmt.Printf("Encapsulating to node %d (%#x) from seclabel %d\n", n.Arg1, n.Arg1, n.Arg2)
	case DBG_LXC_FOUND:
		fmt.Printf("Local container found ifindex %d seclabel %d\n", n.Arg1, n.Arg2)
	case DBG_POLICY_DENIED:
		fmt.Printf("Policy denied from %d to %d\n", n.Arg1, n.Arg2)
	case DBG_CT_LOOKUP:
		fmt.Printf("CT lookup: %s\n", CtInfo(n.Arg1, n.Arg2))
	case DBG_CT_MATCH:
		fmt.Printf("CT entry found lifetime=%d, revnat=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_CT_CREATED:
		fmt.Printf("CT created 1/2: %s\n", CtInfo(n.Arg1, n.Arg2))
	case DBG_CT_CREATED2:
		fmt.Printf("CT created 2/2: %x revnat=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_CT_VERDICT:
		fmt.Printf("CT verdict: %s\n", CtState(int32(n.Arg1)))
	case DBG_ICMP6_HANDLE:
		fmt.Printf("Handling ICMPv6 type=%d\n", n.Arg1)
	case DBG_ICMP6_REQUEST:
		fmt.Printf("ICMPv6 echo request for router offset=%d\n", n.Arg1)
	case DBG_ICMP6_NS:
		fmt.Printf("ICMPv6 neighbour soliciation for address %x:%x\n", n.Arg1, n.Arg2)
	case DBG_ICMP6_TIME_EXCEEDED:
		fmt.Printf("Sending ICMPv6 time exceeded\n")
	case DBG_DECAP:
		fmt.Printf("Tunnel decap: id=%d flowlabel=%x\n", n.Arg1, n.Arg2)
	case DBG_PORT_MAP:
		fmt.Printf("Mapping port from=%d to=%d\n", n.Arg1, n.Arg2)
	case DBG_ERROR_RET:
		fmt.Printf("BPF function %d returned error %d\n", n.Arg1, n.Arg2)
	case DBG_TO_HOST:
		fmt.Printf("Going to host, policy-skip=%d\n", n.Arg1)
	case DBG_TO_STACK:
		fmt.Printf("Going to the stack, policy-skip=%d\n", n.Arg1)
	case DBG_PKT_HASH:
		fmt.Printf("Packet hash=%d (%#x), selected_service=%d\n", n.Arg1, n.Arg1, n.Arg2)
	case DBG_LB6_LOOKUP_MASTER:
		fmt.Printf("Master service lookup, addr.p4=%x key.dport=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_LB6_LOOKUP_MASTER_FAIL:
		fmt.Printf("Master service lookup failed, addr.p2=%x addr.p3=%x\n", n.Arg1, n.Arg2)
	case DBG_LB6_LOOKUP_SLAVE, DBG_LB4_LOOKUP_SLAVE:
		fmt.Printf("Slave service lookup: slave=%d, dport=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_LB6_LOOKUP_SLAVE_SUCCESS:
		fmt.Printf("Slave service lookup result: target.p4=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_LB6_REVERSE_NAT_LOOKUP, DBG_LB4_REVERSE_NAT_LOOKUP:
		fmt.Printf("Reverse NAT lookup, index=%d\n", common.Swab16(uint16(n.Arg1)))
	case DBG_LB6_REVERSE_NAT:
		fmt.Printf("Performing reverse NAT, address.p4=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_LB4_LOOKUP_MASTER:
		fmt.Printf("Master service lookup, addr=%x key.dport=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_LB4_LOOKUP_MASTER_FAIL:
		fmt.Printf("Master service lookup failed\n")
	case DBG_LB4_LOOKUP_SLAVE_SUCCESS:
		fmt.Printf("Slave service lookup result: target=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DBG_LB4_REVERSE_NAT:
		fmt.Printf("Performing reverse NAT, address=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	default:
		fmt.Printf("Unknown message type=%d arg1=%d arg2=%d\n", n.SubType, n.Arg1, n.Arg2)
	}
}

const (
	DebugCaptureLen = 20
)

type DebugCapture struct {
	Type    uint8
	SubType uint8
	Source  uint16
	Hash    uint32
	Len     uint32
	OrigLen uint32
	Arg1    uint32
	// data
}

func (n *DebugCapture) Dump(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d DEBUG: %d bytes ", prefix, n.Hash, n.Source, n.Len)
	switch n.SubType {
	case DBG_CAPTURE_FROM_LXC:
		fmt.Printf("Incoming packet from container ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_FROM_NETDEV:
		fmt.Printf("Incoming packet from netdev ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_FROM_OVERLAY:
		fmt.Printf("Incoming packet from overlay ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_DELIVERY:
		fmt.Printf("Delivery to ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_FROM_LB:
		fmt.Printf("Incoming packet to load balancer on ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_AFTER_V46:
		fmt.Printf("Packet after nat46 ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_AFTER_V64:
		fmt.Printf("Packet after nat64 ifindex %d\n", n.Arg1)
	default:
		fmt.Printf("Unknown message type=%d arg1=%d\n", n.SubType, n.Arg1)
	}

	if n.Len > 0 && len(data) > DebugCaptureLen {
		Dissect(dissect, data[DebugCaptureLen:])
	}
}
