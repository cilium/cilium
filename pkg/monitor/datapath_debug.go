// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"encoding/json"
	"fmt"
	"net"

	// NOTE: syscall is deprecated, but it is replaced by golang.org/x/sys
	//       which reuses syscall.Errno similarly to how we do below.
	"syscall"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/monitor/api"
)

// must be in sync with <bpf/lib/dbg.h>
const (
	DbgCaptureUnspec = iota
	DbgCaptureReserved1
	DbgCaptureReserved2
	DbgCaptureReserved3
	DbgCaptureDelivery
	DbgCaptureFromLb
	DbgCaptureAfterV46
	DbgCaptureAfterV64
	DbgCaptureProxyPre
	DbgCaptureProxyPost
	DbgCaptureSnatPre
	DbgCaptureSnatPost
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
	DbgLb6LookupFrontend
	DbgLb6LookupFrontendFail
	DbgLb6LookupBackendSlot
	DbgLb6LookupBackendSlotSuccess
	DbgLb6LookupBackendSlotV2Fail
	DbgLb6LookupBackendFail
	DbgLb6ReverseNatLookup
	DbgLb6ReverseNat
	DbgLb4LookupFrontend
	DbgLb4LookupFrontendFail
	DbgLb4LookupBackendSlot
	DbgLb4LookupBackendSlotSuccess
	DbgLb4LookupBackendSlotV2Fail
	DbgLb4LookupBackendFail
	DbgLb4ReverseNatLookup
	DbgLb4ReverseNat
	DbgLb4LoopbackSnat
	DbgLb4LoopbackSnatRev
	DbgCtLookup4
	DbgRRBackendSlotSel
	DbgRevProxyLookup
	DbgRevProxyFound
	DbgRevProxyUpdate
	DbgL4Policy
	DbgNetdevInCluster
	DbgNetdevEncap4
	DbgCTLookup41
	DbgCTLookup42
	DbgCTCreated4
	DbgCTLookup61
	DbgCTLookup62
	DbgCTCreated6
	DbgSkipProxy
	DbgL4Create
	DbgIPIDMapFailed4
	DbgIPIDMapFailed6
	DbgIPIDMapSucceed4
	DbgIPIDMapSucceed6
	DbgLbStaleCT
	DbgInheritIdentity
	DbgSkLookup4
	DbgSkLookup6
	DbgSkAssign
	DbgL7LB
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

	return api.DropReason(uint8(state))
}

var tupleFlags = map[int16]string{
	0: "IN",
	1: "OUT",
	2: "RELATED",
}

func ctFlags(flags int16) string {
	s := ""
	for k, v := range tupleFlags {
		if k&flags != 0 {
			if s != "" {
				s += ", "
			}
			s += v
		}
	}
	return s
}

func ctInfo(arg1 uint32, arg2 uint32) string {
	return fmt.Sprintf("sport=%d dport=%d nexthdr=%d flags=%s",
		arg1>>16, arg1&0xFFFF, arg2>>8, ctFlags(int16(arg2&0xFF)))
}

func ctLookup4Info1(n *DebugMsg) string {
	return fmt.Sprintf("src=%s:%d dst=%s:%d", ip4Str(n.Arg1),
		n.Arg3&0xFFFF, ip4Str(n.Arg2), n.Arg3>>16)
}

func ctLookup4Info2(n *DebugMsg) string {
	return fmt.Sprintf("nexthdr=%d flags=%d",
		n.Arg1>>8, n.Arg1&0xFF)
}

func ctCreate4Info(n *DebugMsg) string {
	return fmt.Sprintf("proxy-port=%d revnat=%d src-identity=%d lb=%s",
		n.Arg1>>16, byteorder.NetworkToHost16(uint16(n.Arg1&0xFFFF)), n.Arg2, ip4Str(n.Arg3))
}

func ctLookup6Info1(n *DebugMsg) string {
	return fmt.Sprintf("src=[::%s]:%d dst=[::%s]:%d", ip6Str(n.Arg1),
		n.Arg3&0xFFFF, ip6Str(n.Arg2), n.Arg3>>16)
}

func ctCreate6Info(n *DebugMsg) string {
	return fmt.Sprintf("proxy-port=%d revnat=%d src-identity=%d",
		n.Arg1>>16, byteorder.NetworkToHost16(uint16(n.Arg1&0xFFFF)), n.Arg2)
}

func skAssignInfo(n *DebugMsg) string {
	if n.Arg1 == 0 {
		return "Success"
	}
	return syscall.Errno(n.Arg1).Error()
}

func verdictInfo(arg uint32) string {
	revnat := byteorder.NetworkToHost16(uint16(arg & 0xFFFF))
	return fmt.Sprintf("revnat=%d", revnat)
}

func proxyInfo(arg1 uint32, arg2 uint32) string {
	sport := byteorder.NetworkToHost16(uint16(arg1 >> 16))
	dport := byteorder.NetworkToHost16(uint16(arg1 & 0xFFFF))
	return fmt.Sprintf("sport=%d dport=%d saddr=%s", sport, dport, ip4Str(arg2))
}

func l4CreateInfo(n *DebugMsg) string {
	src := n.Arg1
	dst := n.Arg2
	dport := byteorder.NetworkToHost16(uint16(n.Arg3 >> 16))
	proto := n.Arg3 & 0xFF
	return fmt.Sprintf("src=%d dst=%d dport=%d proto=%d", src, dst, dport, proto)
}

func ip4Str(arg1 uint32) string {
	ip := make(net.IP, 4)
	byteorder.Native.PutUint32(ip, arg1)
	return ip.String()
}

func ip6Str(arg1 uint32) string {
	ip6 := byteorder.NetworkToHost32(arg1)
	return fmt.Sprintf("%x:%x", ip6>>16, ip6&0xFFFF)
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
func (n *DebugMsg) Dump(prefix string, linkMonitor getters.LinkGetter) {
	fmt.Printf("%s MARK %#x FROM %d DEBUG: %s\n", prefix, n.Hash, n.Source, n.Message(linkMonitor))
}

// Message returns the debug message in a human-readable format
func (n *DebugMsg) Message(linkMonitor getters.LinkGetter) string {
	switch n.SubType {
	case DbgGeneric:
		return fmt.Sprintf("No message, arg1=%d (%#x) arg2=%d (%#x)", n.Arg1, n.Arg1, n.Arg2, n.Arg2)
	case DbgLocalDelivery:
		return fmt.Sprintf("Attempting local delivery for container id %d from seclabel %d", n.Arg1, n.Arg2)
	case DbgEncap:
		return fmt.Sprintf("Encapsulating to node %d (%#x) from seclabel %d", n.Arg1, n.Arg1, n.Arg2)
	case DbgLxcFound:
		var ifname string
		if linkMonitor != nil {
			ifname = linkMonitor.Name(n.Arg1)
		}
		return fmt.Sprintf("Local container found ifindex %s seclabel %d", ifname, byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgPolicyDenied:
		return fmt.Sprintf("Policy evaluation would deny packet from %d to %d", n.Arg1, n.Arg2)
	case DbgCtLookup:
		return fmt.Sprintf("CT lookup: %s", ctInfo(n.Arg1, n.Arg2))
	case DbgCtLookupRev:
		return fmt.Sprintf("CT reverse lookup: %s", ctInfo(n.Arg1, n.Arg2))
	case DbgCtLookup4:
		return fmt.Sprintf("CT lookup address: %s", ip4Str(n.Arg1))
	case DbgCtMatch:
		return fmt.Sprintf("CT entry found lifetime=%d, %s", n.Arg1,
			verdictInfo(n.Arg2))
	case DbgCtCreated:
		return fmt.Sprintf("CT created 1/2: %s %s",
			ctInfo(n.Arg1, n.Arg2), verdictInfo(n.Arg3))
	case DbgCtCreated2:
		return fmt.Sprintf("CT created 2/2: %s revnat=%d", ip4Str(n.Arg1), byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgCtVerdict:
		return fmt.Sprintf("CT verdict: %s, %s",
			ctState(n.Arg1), verdictInfo(n.Arg2))
	case DbgIcmp6Handle:
		return fmt.Sprintf("Handling ICMPv6 type=%d", n.Arg1)
	case DbgIcmp6Request:
		return fmt.Sprintf("ICMPv6 echo request for router offset=%d", n.Arg1)
	case DbgIcmp6Ns:
		return fmt.Sprintf("ICMPv6 neighbour soliciation for address %x:%x", n.Arg1, n.Arg2)
	case DbgIcmp6TimeExceeded:
		return "Sending ICMPv6 time exceeded"
	case DbgDecap:
		return fmt.Sprintf("Tunnel decap: id=%d flowlabel=%x", n.Arg1, n.Arg2)
	case DbgPortMap:
		return fmt.Sprintf("Mapping port from=%d to=%d", n.Arg1, n.Arg2)
	case DbgErrorRet:
		return fmt.Sprintf("BPF function %d returned error %d", n.Arg1, n.Arg2)
	case DbgToHost:
		return fmt.Sprintf("Going to host, policy-skip=%d", n.Arg1)
	case DbgToStack:
		return fmt.Sprintf("Going to the stack, policy-skip=%d", n.Arg1)
	case DbgPktHash:
		return fmt.Sprintf("Packet hash=%d (%#x), selected_service=%d", n.Arg1, n.Arg1, n.Arg2)
	case DbgRRBackendSlotSel:
		return fmt.Sprintf("RR backend slot selection hash=%d (%#x), selected_service=%d", n.Arg1, n.Arg1, n.Arg2)
	case DbgLb6LookupFrontend:
		return fmt.Sprintf("Frontend service lookup, addr.p4=%x key.dport=%d", n.Arg1, byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb6LookupFrontendFail:
		return fmt.Sprintf("Frontend service lookup failed, addr.p2=%x addr.p3=%x", n.Arg1, n.Arg2)
	case DbgLb6LookupBackendSlot, DbgLb4LookupBackendSlot:
		return fmt.Sprintf("Service backend slot lookup: slot=%d, dport=%d", n.Arg1, byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb6LookupBackendSlotV2Fail, DbgLb4LookupBackendSlotV2Fail:
		return fmt.Sprintf("Service backend slot lookup failed: slot=%d, dport=%d", n.Arg1, byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb6LookupBackendFail, DbgLb4LookupBackendFail:
		return fmt.Sprintf("Backend service lookup failed: backend_id=%d", n.Arg1)
	case DbgLb6LookupBackendSlotSuccess:
		return fmt.Sprintf("Service backend slot lookup result: target.p4=%x port=%d", n.Arg1, byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb6ReverseNatLookup, DbgLb4ReverseNatLookup:
		return fmt.Sprintf("Reverse NAT lookup, index=%d", byteorder.NetworkToHost16(uint16(n.Arg1)))
	case DbgLb6ReverseNat:
		return fmt.Sprintf("Performing reverse NAT, address.p4=%x port=%d", n.Arg1, byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb4LookupFrontend:
		return fmt.Sprintf("Frontend service lookup, addr=%s key.dport=%d", ip4Str(n.Arg1), byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb4LookupFrontendFail:
		return "Frontend service lookup failed"
	case DbgLb4LookupBackendSlotSuccess:
		return fmt.Sprintf("Service backend slot lookup result: target=%s port=%d", ip4Str(n.Arg1), byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb4ReverseNat:
		return fmt.Sprintf("Performing reverse NAT, address=%s port=%d", ip4Str(n.Arg1), byteorder.NetworkToHost16(uint16(n.Arg2)))
	case DbgLb4LoopbackSnat:
		return fmt.Sprintf("Loopback SNAT from=%s to=%s", ip4Str(n.Arg1), ip4Str(n.Arg2))
	case DbgLb4LoopbackSnatRev:
		return fmt.Sprintf("Loopback reverse SNAT from=%s to=%s", ip4Str(n.Arg1), ip4Str(n.Arg2))
	case DbgRevProxyLookup:
		return fmt.Sprintf("Reverse proxy lookup %s nexthdr=%d",
			proxyInfo(n.Arg1, n.Arg2), n.Arg3)
	case DbgRevProxyFound:
		return fmt.Sprintf("Reverse proxy entry found, orig-daddr=%s orig-dport=%d", ip4Str(n.Arg1), n.Arg2)
	case DbgRevProxyUpdate:
		return fmt.Sprintf("Reverse proxy updated %s nexthdr=%d",
			proxyInfo(n.Arg1, n.Arg2), n.Arg3)
	case DbgL4Policy:
		return fmt.Sprintf("Resolved L4 policy to: %d / %s",
			byteorder.NetworkToHost16(uint16(n.Arg1)), ctDirection[int(n.Arg2)])
	case DbgNetdevInCluster:
		return fmt.Sprintf("Destination is inside cluster prefix, source identity: %d", n.Arg1)
	case DbgNetdevEncap4:
		return fmt.Sprintf("Attempting encapsulation, lookup key: %s, identity: %d", ip4Str(n.Arg1), n.Arg2)
	case DbgCTLookup41:
		return fmt.Sprintf("Conntrack lookup 1/2: %s", ctLookup4Info1(n))
	case DbgCTLookup42:
		return fmt.Sprintf("Conntrack lookup 2/2: %s", ctLookup4Info2(n))
	case DbgCTCreated4:
		return fmt.Sprintf("Conntrack create: %s", ctCreate4Info(n))
	case DbgCTLookup61:
		return fmt.Sprintf("Conntrack lookup 1/2: %s", ctLookup6Info1(n))
	case DbgCTLookup62:
		return fmt.Sprintf("Conntrack lookup 2/2: %s", ctLookup4Info2(n))
	case DbgCTCreated6:
		return fmt.Sprintf("Conntrack create: %s", ctCreate6Info(n))
	case DbgSkipProxy:
		return fmt.Sprintf("Skipping proxy, tc_index is set=%x", n.Arg1)
	case DbgL4Create:
		return fmt.Sprintf("Matched L4 policy; creating conntrack %s", l4CreateInfo(n))
	case DbgIPIDMapFailed4:
		return fmt.Sprintf("Failed to map addr=%s to identity", ip4Str(n.Arg1))
	case DbgIPIDMapFailed6:
		return fmt.Sprintf("Failed to map addr.p4=[::%s] to identity", ip6Str(n.Arg1))
	case DbgIPIDMapSucceed4:
		return fmt.Sprintf("Successfully mapped addr=%s to identity=%d", ip4Str(n.Arg1), n.Arg2)
	case DbgIPIDMapSucceed6:
		return fmt.Sprintf("Successfully mapped addr.p4=[::%s] to identity=%d", ip6Str(n.Arg1), n.Arg2)
	case DbgLbStaleCT:
		return fmt.Sprintf("Stale CT entry found stale_ct.rev_nat_id=%d, svc.rev_nat_id=%d", n.Arg2, n.Arg1)
	case DbgInheritIdentity:
		return fmt.Sprintf("Inheriting identity=%d from stack", n.Arg1)
	case DbgSkLookup4:
		return fmt.Sprintf("Socket lookup: %s", ctLookup4Info1(n))
	case DbgSkLookup6:
		return fmt.Sprintf("Socket lookup: %s", ctLookup6Info1(n))
	case DbgSkAssign:
		return fmt.Sprintf("Socket assign: %s", skAssignInfo(n))
	case DbgL7LB:
		return fmt.Sprintf("L7 LB from %s to %s: proxy port %d", ip4Str(n.Arg1), ip4Str(n.Arg2), n.Arg3)
	default:
		return fmt.Sprintf("Unknown message type=%d arg1=%d arg2=%d", n.SubType, n.Arg1, n.Arg2)
	}
}

func (n *DebugMsg) getJSON(cpuPrefix string, linkMonitor getters.LinkGetter) string {
	return fmt.Sprintf(`{"cpu":%q,"type":"debug","message":%q}`,
		cpuPrefix, n.Message(linkMonitor))
}

// DumpJSON prints notification in json format
func (n *DebugMsg) DumpJSON(cpuPrefix string, linkMonitor getters.LinkGetter) {
	fmt.Println(n.getJSON(cpuPrefix, linkMonitor))
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

// DumpInfo prints a summary of the capture messages.
func (n *DebugCapture) DumpInfo(data []byte, linkMonitor getters.LinkGetter) {
	prefix := n.infoPrefix(linkMonitor)

	if len(prefix) > 0 {
		fmt.Printf("%s: %s\n", prefix, GetConnectionSummary(data[DebugCaptureLen:]))
	}
}

func (n *DebugCapture) infoPrefix(linkMonitor getters.LinkGetter) string {
	switch n.SubType {
	case DbgCaptureDelivery:
		ifname := linkMonitor.Name(n.Arg1)
		return fmt.Sprintf("-> %s", ifname)

	case DbgCaptureFromLb:
		ifname := linkMonitor.Name(n.Arg1)
		return fmt.Sprintf("<- load-balancer %s", ifname)

	case DbgCaptureAfterV46:
		return fmt.Sprintf("== v4->v6 %d", n.Arg1)

	case DbgCaptureAfterV64:
		return fmt.Sprintf("== v6->v4 %d", n.Arg1)

	case DbgCaptureProxyPost:
		return fmt.Sprintf("-> proxy port %d", byteorder.NetworkToHost16(uint16(n.Arg1)))
	default:
		return ""
	}
}

// DumpVerbose prints the captured packet in human readable format
func (n *DebugCapture) DumpVerbose(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d DEBUG: %d bytes, ", prefix, n.Hash, n.Source, n.Len)
	fmt.Println(n.subTypeString())

	if n.Len > 0 && len(data) > DebugCaptureLen {
		Dissect(dissect, data[DebugCaptureLen:])
	}
}

func (n *DebugCapture) subTypeString() string {
	switch n.SubType {
	case DbgCaptureDelivery:
		return fmt.Sprintf("Delivery to ifindex %d", n.Arg1)
	case DbgCaptureFromLb:
		return fmt.Sprintf("Incoming packet to load balancer on ifindex %d", n.Arg1)
	case DbgCaptureAfterV46:
		return fmt.Sprintf("Packet after nat46 ifindex %d", n.Arg1)
	case DbgCaptureAfterV64:
		return fmt.Sprintf("Packet after nat64 ifindex %d", n.Arg1)
	case DbgCaptureProxyPre:
		return fmt.Sprintf("Packet to proxy port %d (Pre)", byteorder.NetworkToHost16(uint16(n.Arg1)))
	case DbgCaptureProxyPost:
		return fmt.Sprintf("Packet to proxy port %d (Post)", byteorder.NetworkToHost16(uint16(n.Arg1)))
	case DbgCaptureSnatPre:
		return fmt.Sprintf("Packet going into snat engine on ifindex %d", n.Arg1)
	case DbgCaptureSnatPost:
		return fmt.Sprintf("Packet coming from snat engine on ifindex %d", n.Arg1)
	default:
		return fmt.Sprintf("Unknown message type=%d arg1=%d", n.SubType, n.Arg1)
	}
}

func (n *DebugCapture) getJSON(data []byte, cpuPrefix string, linkMonitor getters.LinkGetter) (string, error) {

	v := DebugCaptureToVerbose(n, linkMonitor)
	v.CPUPrefix = cpuPrefix
	v.Summary = GetConnectionSummary(data[DebugCaptureLen:])

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (n *DebugCapture) DumpJSON(data []byte, cpuPrefix string, linkMonitor getters.LinkGetter) {
	resp, err := n.getJSON(data, cpuPrefix, linkMonitor)
	if err != nil {
		fmt.Println(fmt.Sprintf(`{"type":"debug_capture_error","message":%q}`, err.Error()))
		return
	}
	fmt.Println(resp)
}

// DebugCaptureVerbose represents a json notification printed by monitor
type DebugCaptureVerbose struct {
	CPUPrefix string `json:"cpu,omitempty"`
	Type      string `json:"type,omitempty"`
	Mark      string `json:"mark,omitempty"`
	Message   string `json:"message,omitempty"`
	Prefix    string `json:"prefix,omitempty"`

	Source uint16 `json:"source"`
	Bytes  uint32 `json:"bytes"`

	Summary string `json:"summary,omitempty"`
}

// DebugCaptureToVerbose creates verbose notification from base TraceNotify
func DebugCaptureToVerbose(n *DebugCapture, linkMonitor getters.LinkGetter) DebugCaptureVerbose {
	return DebugCaptureVerbose{
		Type:    "capture",
		Mark:    fmt.Sprintf("%#x", n.Hash),
		Source:  n.Source,
		Bytes:   n.Len,
		Message: n.subTypeString(),
		Prefix:  n.infoPrefix(linkMonitor),
	}
}
