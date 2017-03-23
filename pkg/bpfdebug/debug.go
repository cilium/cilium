// Copyright 2016-2017 Authors of Cilium
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

package bpfdebug

import (
	"fmt"

	"github.com/cilium/cilium/common"
)

// Must be synchronized with <bpf/lib/common.h>
const (
	MessageTypeUnspec = iota
	MessageTypeDrop
	MessageTypeDebug
	MessageTypeCapture
)

// must be in sync with <bpf/lib/dbg.h>
const (
	DbgCaptureUnspec = iota
	DbgCaptureFromLxc
	DbgCaptureFromNetdev
	DbgCaptureFromOverlay
	DbgCaptureDelivery
	DbgCaptureFromLb
	DbgCaptureAfterV46
	DbgCaptureAfterV64
	DbgCaptureProxyPre
	DbgCaptureProxyPost
)

// must be in sync with <bpf/lib/dbg.h>
const (
	DbgUnspec = iota
	DbgGeneric
	DbgLocalDelivery
	DbgEncap
	DbgLxcFound
	DbgPolicyDenied
	DbgCtLookup
	DbgCtMatch
	DbgCtCreated
	DbgCtCreated2
	DbgIcmp6Handle
	DbgIcmp6Request
	DbgIcmp6Ns
	DbgIcmp6TimeExceeded
	DbgCtVerdict
	DbgDecap
	DbgPortMap
	DbgErrorRet
	DbgToHost
	DbgToStack
	DbgPktHash
	DbgLb6LookupMaster
	DbgLb6LookupMasterFail
	DbgLb6LookupSlave
	DbgLb6LookupSlaveSuccess
	DbgLb6ReverseNatLookup
	DbgLb6ReverseNat
	DbgLb4LookupMaster
	DbgLb4LookupMasterFail
	DbgLb4LookupSlave
	DbgLb4LookupSlaveSuccess
	DbgLb4ReverseNatLookup
	DbgLb4ReverseNat
	DbgLb4LoopbackSnat
	DbgLb4LoopbackSnatRev
	DbgCtLookup4
	DbgRRSlaveSel
	DbgRevProxyLookup
	DbgRevProxyFound
	DbgRevProxyUpdate
	DbgL4Policy
)

// must be in sync with <bpf/lib/conntrack.h>
const (
	CtNew uint32 = iota
	CtEstablished
	CtReply
	CtRelated
)

var ctStateText = map[uint32]string{
	CtNew:         "New",
	CtEstablished: "Established",
	CtReply:       "Reply",
	CtRelated:     "Related",
}

func ctState(state uint32) string {
	txt, ok := ctStateText[state]
	if ok {
		return txt
	}

	return dropReason(uint8(state))
}

func ctInfo(arg1 uint32, arg2 uint32) string {
	return fmt.Sprintf("sport=%d dport=%d nexthdr=%d flags=%d",
		arg1>>16, arg1&0xFFFF, arg2>>8, arg2&0xFF)
}

func proxyInfo(arg1 uint32, arg2 uint32) string {
	sport := common.Swab16(uint16(arg1 >> 16))
	dport := common.Swab16(uint16(arg1 & 0xFFFF))
	return fmt.Sprintf("sport=%d dport=%d saddr=%x", sport, dport, arg2)
}

// DebugMsg is the message format of the debug message found in the BPF ring buffer
type DebugMsg struct {
	Type    uint8
	SubType uint8
	Source  uint16
	Hash    uint32
	Arg1    uint32
	Arg2    uint32
}

// Dump prints the debug message in a human readable format.
func (n *DebugMsg) Dump(data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d DEBUG: ", prefix, n.Hash, n.Source)
	switch n.SubType {
	case DbgGeneric:
		fmt.Printf("No message, arg1=%d (%#x) arg2=%d (%#x)\n", n.Arg1, n.Arg1, n.Arg2, n.Arg2)
	case DbgLocalDelivery:
		fmt.Printf("Attempting local delivery for container id %d from seclabel %d\n", n.Arg1, n.Arg2)
	case DbgEncap:
		fmt.Printf("Encapsulating to node %d (%#x) from seclabel %d\n", n.Arg1, n.Arg1, n.Arg2)
	case DbgLxcFound:
		fmt.Printf("Local container found ifindex %d seclabel %d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgPolicyDenied:
		fmt.Printf("Policy denied from %d to %d\n", n.Arg1, n.Arg2)
	case DbgCtLookup:
		fmt.Printf("CT lookup: %s\n", ctInfo(n.Arg1, n.Arg2))
	case DbgCtLookup4:
		fmt.Printf("CT lookup address: %x\n", n.Arg1)
	case DbgCtMatch:
		fmt.Printf("CT entry found lifetime=%d, revnat=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgCtCreated:
		fmt.Printf("CT created 1/2: %s\n", ctInfo(n.Arg1, n.Arg2))
	case DbgCtCreated2:
		fmt.Printf("CT created 2/2: %x revnat=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgCtVerdict:
		fmt.Printf("CT verdict: %s\n", ctState(n.Arg1))
	case DbgIcmp6Handle:
		fmt.Printf("Handling ICMPv6 type=%d\n", n.Arg1)
	case DbgIcmp6Request:
		fmt.Printf("ICMPv6 echo request for router offset=%d\n", n.Arg1)
	case DbgIcmp6Ns:
		fmt.Printf("ICMPv6 neighbour soliciation for address %x:%x\n", n.Arg1, n.Arg2)
	case DbgIcmp6TimeExceeded:
		fmt.Printf("Sending ICMPv6 time exceeded\n")
	case DbgDecap:
		fmt.Printf("Tunnel decap: id=%d flowlabel=%x\n", n.Arg1, n.Arg2)
	case DbgPortMap:
		fmt.Printf("Mapping port from=%d to=%d\n", n.Arg1, n.Arg2)
	case DbgErrorRet:
		fmt.Printf("BPF function %d returned error %d\n", n.Arg1, n.Arg2)
	case DbgToHost:
		fmt.Printf("Going to host, policy-skip=%d\n", n.Arg1)
	case DbgToStack:
		fmt.Printf("Going to the stack, policy-skip=%d\n", n.Arg1)
	case DbgPktHash:
		fmt.Printf("Packet hash=%d (%#x), selected_service=%d\n", n.Arg1, n.Arg1, n.Arg2)
	case DbgRRSlaveSel:
		fmt.Printf("RR slave selection hash=%d (%#x), selected_service=%d\n", n.Arg1, n.Arg1, n.Arg2)
	case DbgLb6LookupMaster:
		fmt.Printf("Master service lookup, addr.p4=%x key.dport=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb6LookupMasterFail:
		fmt.Printf("Master service lookup failed, addr.p2=%x addr.p3=%x\n", n.Arg1, n.Arg2)
	case DbgLb6LookupSlave, DbgLb4LookupSlave:
		fmt.Printf("Slave service lookup: slave=%d, dport=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb6LookupSlaveSuccess:
		fmt.Printf("Slave service lookup result: target.p4=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb6ReverseNatLookup, DbgLb4ReverseNatLookup:
		fmt.Printf("Reverse NAT lookup, index=%d\n", common.Swab16(uint16(n.Arg1)))
	case DbgLb6ReverseNat:
		fmt.Printf("Performing reverse NAT, address.p4=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb4LookupMaster:
		fmt.Printf("Master service lookup, addr=%x key.dport=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb4LookupMasterFail:
		fmt.Printf("Master service lookup failed\n")
	case DbgLb4LookupSlaveSuccess:
		fmt.Printf("Slave service lookup result: target=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb4ReverseNat:
		fmt.Printf("Performing reverse NAT, address=%x port=%d\n", n.Arg1, common.Swab16(uint16(n.Arg2)))
	case DbgLb4LoopbackSnat:
		fmt.Printf("Loopback SNAT from=%x to=%x\n", n.Arg1, n.Arg2)
	case DbgLb4LoopbackSnatRev:
		fmt.Printf("Loopback reverse SNAT from=%x to=%x\n", n.Arg1, n.Arg2)
	case DbgRevProxyLookup:
		fmt.Printf("Reverse proxy lookup, %s\n", proxyInfo(n.Arg1, n.Arg2))
	case DbgRevProxyFound:
		fmt.Printf("Reverse proxy entry found, orig-daddr=%x orig-dport=%d\n", n.Arg1, n.Arg2)
	case DbgRevProxyUpdate:
		fmt.Printf("Reverse proxy updated, %s\n", proxyInfo(n.Arg1, n.Arg2))
	case DbgL4Policy:
		fmt.Printf("Resolved L4 policy to: %d / %d\n", common.Swab16(uint16(n.Arg1)), n.Arg2)
	default:
		fmt.Printf("Unknown message type=%d arg1=%d arg2=%d\n", n.SubType, n.Arg1, n.Arg2)
	}
}

const (
	// DebugCaptureLen is the amount of packet data in a packet capture message
	DebugCaptureLen = 20
)

// DebugCapture is the metadata sent along with a captured packet frame
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

// Dump prints the captured packet in human readable format
func (n *DebugCapture) Dump(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d DEBUG: %d bytes ", prefix, n.Hash, n.Source, n.Len)
	switch n.SubType {
	case DbgCaptureFromLxc:
		fmt.Printf("Incoming packet from container ifindex %d\n", n.Arg1)
	case DbgCaptureFromNetdev:
		fmt.Printf("Incoming packet from netdev ifindex %d\n", n.Arg1)
	case DbgCaptureFromOverlay:
		fmt.Printf("Incoming packet from overlay ifindex %d\n", n.Arg1)
	case DbgCaptureDelivery:
		fmt.Printf("Delivery to ifindex %d\n", n.Arg1)
	case DbgCaptureFromLb:
		fmt.Printf("Incoming packet to load balancer on ifindex %d\n", n.Arg1)
	case DbgCaptureAfterV46:
		fmt.Printf("Packet after nat46 ifindex %d\n", n.Arg1)
	case DbgCaptureAfterV64:
		fmt.Printf("Packet after nat64 ifindex %d\n", n.Arg1)
	case DbgCaptureProxyPre:
		fmt.Printf("Packet to proxy port %d (Pre)\n", common.Swab16(uint16(n.Arg1)))
	case DbgCaptureProxyPost:
		fmt.Printf("Packet to proxy port %d (Post)\n", common.Swab16(uint16(n.Arg1)))
	default:
		fmt.Printf("Unknown message type=%d arg1=%d\n", n.SubType, n.Arg1)
	}

	if n.Len > 0 && len(data) > DebugCaptureLen {
		Dissect(dissect, data[DebugCaptureLen:])
	}
}
