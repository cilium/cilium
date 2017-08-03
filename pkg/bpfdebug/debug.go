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
	"net"

	"github.com/cilium/cilium/pkg/byteorder"
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
	DbgCtLookupRev
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
	DbgNetdevInCluster
	DbgNetdevEncap4
	DbgCTLookup41
	DbgCTLookup42
	DbgCTCreated4
	DbgErrAbort
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

const (
	ctEgress  = 0
	ctIngress = 1
)

var ctDirection = map[int]string{
	ctEgress:  "egress",
	ctIngress: "ingress",
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

func ctLookup4Info1(n *DebugMsg) string {
	return fmt.Sprintf("src=%s:%d dst=%s:%d", ip4Str(n.Arg2),
		n.Arg3&0xFFFF, ip4Str(n.Arg1), n.Arg3>>16)
}

func ctLookup4Info2(n *DebugMsg) string {
	return fmt.Sprintf("nexthdr=%d flags=%d",
		n.Arg1>>8, n.Arg1&0xFF)
}

func ctCreate4Info(n *DebugMsg) string {
	return fmt.Sprintf("proxy-port=%d revnat=%d src-identity=%d lb=%s",
		n.Arg1>>16, n.Arg1&0xFFFF, n.Arg2, ip4Str(n.Arg3))
}

func verdictInfo(arg uint32) string {
	proxyPort := byteorder.NetworkToHost(uint16(arg >> 16))
	revnat := byteorder.NetworkToHost(uint16(arg & 0xFFFF))
	return fmt.Sprintf("proxy_port=%d revnat=%d", proxyPort, revnat)
}

func proxyInfo(arg1 uint32, arg2 uint32) string {
	sport := byteorder.NetworkToHost(uint16(arg1 >> 16))
	dport := byteorder.NetworkToHost(uint16(arg1 & 0xFFFF))
	return fmt.Sprintf("sport=%d dport=%d saddr=%s", sport, dport, ip4Str(arg2))
}

func ip4Str(arg1 uint32) string {
	ip := make(net.IP, 4)
	byteorder.NetworkToHostPut(ip, arg1)
	return ip.String()

}

// DebugMsg is the message format of the debug message found in the BPF ring buffer
type DebugMsg struct {
	Type    uint8
	SubType uint8
	Source  uint16
	Hash    uint32
	Arg1    uint32
	Arg2    uint32
	Arg3    uint32
}

// DumpInfo prints a summary of a subset of the debug messages which are related
// to sending, not processing, of packets.
func (n *DebugMsg) DumpInfo(data []byte) {
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
		fmt.Printf("Local container found ifindex %d seclabel %d\n", n.Arg1, byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgPolicyDenied:
		fmt.Printf("Policy evaluation would deny packet from %d to %d\n", n.Arg1, n.Arg2)
	case DbgCtLookup:
		fmt.Printf("CT lookup: %s\n", ctInfo(n.Arg1, n.Arg2))
	case DbgCtLookupRev:
		fmt.Printf("CT reverse lookup: %s\n", ctInfo(n.Arg1, n.Arg2))
	case DbgCtLookup4:
		fmt.Printf("CT lookup address: %s\n", ip4Str(n.Arg1))
	case DbgCtMatch:
		fmt.Printf("CT entry found lifetime=%d, %s\n", n.Arg1,
			verdictInfo(n.Arg2))
	case DbgCtCreated:
		fmt.Printf("CT created 1/2: %s %s\n",
			ctInfo(n.Arg1, n.Arg2), verdictInfo(n.Arg3))
	case DbgCtCreated2:
		fmt.Printf("CT created 2/2: %s revnat=%d\n", ip4Str(n.Arg1), byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgCtVerdict:
		fmt.Printf("CT verdict: %s, %s\n",
			ctState(n.Arg1), verdictInfo(n.Arg2))
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
		fmt.Printf("Master service lookup, addr.p4=%x key.dport=%d\n", n.Arg1, byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb6LookupMasterFail:
		fmt.Printf("Master service lookup failed, addr.p2=%x addr.p3=%x\n", n.Arg1, n.Arg2)
	case DbgLb6LookupSlave, DbgLb4LookupSlave:
		fmt.Printf("Slave service lookup: slave=%d, dport=%d\n", n.Arg1, byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb6LookupSlaveSuccess:
		fmt.Printf("Slave service lookup result: target.p4=%x port=%d\n", n.Arg1, byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb6ReverseNatLookup, DbgLb4ReverseNatLookup:
		fmt.Printf("Reverse NAT lookup, index=%d\n", byteorder.NetworkToHost(uint16(n.Arg1)))
	case DbgLb6ReverseNat:
		fmt.Printf("Performing reverse NAT, address.p4=%x port=%d\n", n.Arg1, byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb4LookupMaster:
		fmt.Printf("Master service lookup, addr=%s key.dport=%d\n", ip4Str(n.Arg1), byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb4LookupMasterFail:
		fmt.Printf("Master service lookup failed\n")
	case DbgLb4LookupSlaveSuccess:
		fmt.Printf("Slave service lookup result: target=%s port=%d\n", ip4Str(n.Arg1), byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb4ReverseNat:
		fmt.Printf("Performing reverse NAT, address=%s port=%d\n", ip4Str(n.Arg1), byteorder.NetworkToHost(uint16(n.Arg2)))
	case DbgLb4LoopbackSnat:
		fmt.Printf("Loopback SNAT from=%s to=%s\n", ip4Str(n.Arg1), ip4Str(n.Arg2))
	case DbgLb4LoopbackSnatRev:
		fmt.Printf("Loopback reverse SNAT from=%s to=%s\n", ip4Str(n.Arg1), ip4Str(n.Arg2))
	case DbgRevProxyLookup:
		fmt.Printf("Reverse proxy lookup %s nexthdr=%d\n",
			proxyInfo(n.Arg1, n.Arg2), n.Arg3)
	case DbgRevProxyFound:
		fmt.Printf("Reverse proxy entry found, orig-daddr=%s orig-dport=%d\n", ip4Str(n.Arg1), n.Arg2)
	case DbgRevProxyUpdate:
		fmt.Printf("Reverse proxy updated %s nexthdr=%d\n",
			proxyInfo(n.Arg1, n.Arg2), n.Arg3)
	case DbgL4Policy:
		fmt.Printf("Resolved L4 policy to: %d / %s\n",
			byteorder.NetworkToHost(uint16(n.Arg1)), ctDirection[int(n.Arg2)])
	case DbgNetdevInCluster:
		fmt.Printf("Destination is inside cluster prefix, source identity: %d\n", n.Arg1)
	case DbgNetdevEncap4:
		fmt.Printf("Attempting encapsulation, lookup key: %s, identity: %d\n", ip4Str(n.Arg1), n.Arg2)
	case DbgCTLookup41:
		fmt.Printf("Conntrack lookup 1/2: %s\n", ctLookup4Info1(n))
	case DbgCTLookup42:
		fmt.Printf("Conntrack lookup 2/2: %s\n", ctLookup4Info2(n))
	case DbgCTCreated4:
		fmt.Printf("Conntrack create: %s\n", ctCreate4Info(n))
	case DbgErrAbort:
		fmt.Printf("Aborted processing on error %d\n", int(n.Arg1))
	default:
		fmt.Printf("Unknown message type=%d arg1=%d arg2=%d\n", n.SubType, n.Arg1, n.Arg2)
	}
}

const (
	// DebugCaptureLen is the amount of packet data in a packet capture message
	DebugCaptureLen = 24
)

// DebugCapture is the metadata sent along with a captured packet frame
type DebugCapture struct {
	Type    uint8
	SubType uint8
	// Source, if populated, is the ID of the source endpoint.
	Source  uint16
	Hash    uint32
	Len     uint32
	OrigLen uint32
	Arg1    uint32
	Arg2    uint32
	// data
}

type endpointInfo struct {
	name     string
	identity int
}

var (
	ifindexMap = map[int]endpointInfo{}
)

// DumpInfo prints a summary of the capture messages.
func (n *DebugCapture) DumpInfo(data []byte) {
	switch n.SubType {
	case DbgCaptureFromLxc:
		ifindexMap[int(n.Arg1)] = endpointInfo{
			name:     fmt.Sprintf("endpoint %d", n.Source),
			identity: int(n.Arg2),
		}
		fmt.Printf("<- endpoint %d, identity %d", n.Source, n.Arg2)

	case DbgCaptureFromNetdev:
		ifindexMap[int(n.Arg1)] = endpointInfo{
			name: fmt.Sprintf("netdev %d", n.Arg1),
		}
		fmt.Printf("<- netdev %d", n.Arg1)

	case DbgCaptureFromOverlay:
		ifindexMap[int(n.Arg1)] = endpointInfo{
			name: fmt.Sprintf("overlay %d", n.Arg1),
		}
		fmt.Printf("<- overlay %d", n.Arg1)

	case DbgCaptureDelivery:
		// Try to map ifindex to string
		if indexInfo, ok := ifindexMap[int(n.Arg1)]; ok {
			fmt.Printf("-> %s", indexInfo.name)
			if indexInfo.identity != 0 {
				fmt.Printf(", identity %d", indexInfo.identity)
			}
		} else {
			fmt.Printf("-> ifindex %d", n.Arg1)
		}

	case DbgCaptureFromLb:
		ifindexMap[int(n.Arg1)] = endpointInfo{
			name: fmt.Sprintf("load-balancer %d", n.Arg1),
		}
		fmt.Printf("<- load-balancer %d", n.Arg1)

	case DbgCaptureAfterV46:
		fmt.Printf("== v4->v6 %d", n.Arg1)

	case DbgCaptureAfterV64:
		fmt.Printf("== v6->v4 %d", n.Arg1)

	case DbgCaptureProxyPost:
		fmt.Printf("-> proxy port %d", byteorder.NetworkToHost(uint16(n.Arg1)))
	default:
		return
	}

	fmt.Printf(": %s\n", GetConnectionSummary(data[DebugCaptureLen:]))

}

// Dump prints the captured packet in human readable format
func (n *DebugCapture) DumpVerbose(dissect bool, data []byte, prefix string) {
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
		fmt.Printf("Packet to proxy port %d (Pre)\n", byteorder.NetworkToHost(uint16(n.Arg1)))
	case DbgCaptureProxyPost:
		fmt.Printf("Packet to proxy port %d (Post)\n", byteorder.NetworkToHost(uint16(n.Arg1)))
	default:
		fmt.Printf("Unknown message type=%d arg1=%d\n", n.SubType, n.Arg1)
	}

	if n.Len > 0 && len(data) > DebugCaptureLen {
		Dissect(dissect, data[DebugCaptureLen:])
	}
}
