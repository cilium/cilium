package bpf

import (
	"fmt"
)

const (
	DBG_CAPTURE_UNSPEC = iota
	DBG_CAPTURE_FROM_LXC
	DBG_CAPTURE_FROM_NETDEV
	DBG_CAPTURE_FROM_OVERLAY
	DBG_CAPTURE_DELIVERY
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
	DBG_ICMP6_HANDLE
	DBG_ICMP6_REQUEST
	DBG_ICMP6_NS
	DBG_ICMP6_TIME_EXCEEDED
	DBG_CT_VERDICT
	DBG_DECAP
	DBG_PORT_MAP
	DBG_ERROR_RET
)

// must be in sync with <bpf/lib/conntrack.h>
const (
	CT_NEW uint32 = iota
	CT_ESTABLISHED
	CT_REPLY
	CT_RELATED
)

var ctState = map[uint32]string{
	CT_NEW:         "New",
	CT_ESTABLISHED: "Established",
	CT_REPLY:       "Reply",
	CT_RELATED:     "Related",
}

type DebugMsg struct {
	Type    uint8
	SubType uint8
	Source  uint16
	Arg1    uint32
	Arg2    uint32
}

func (n *DebugMsg) Dump(data []byte, prefix string) {
	fmt.Printf("%s FROM %d DEBUG: ", prefix, n.Source)
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
		fmt.Printf("CT lookup sport=%d dport=%d\n", n.Arg1, n.Arg2)
	case DBG_CT_MATCH:
		fmt.Printf("CT entry found flags=%#x IPv6=[...]:%x\n", n.Arg1, n.Arg2)
	case DBG_CT_CREATED:
		fmt.Printf("CT created proto=%d flags=%#x\n", n.Arg1, n.Arg2)
	case DBG_CT_VERDICT:
		fmt.Printf("CT verdict: %s\n", ctState[n.Arg1])
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
	default:
		fmt.Printf("Unknown message type=%d arg1=%d arg2=%d\n", n.SubType, n.Arg1, n.Arg2)
	}
}

type DebugCapture struct {
	Type    uint8
	SubType uint8
	Source  uint16
	Len     uint32
	OrigLen uint32
	Arg1    uint32
	// data
}

func (n *DebugCapture) Dump(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s FROM %d DEBUG: %d bytes ", prefix, n.Source, n.Len)
	switch n.SubType {
	case DBG_CAPTURE_FROM_LXC:
		fmt.Printf("Incoming packet from container ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_FROM_NETDEV:
		fmt.Printf("Incoming packet from netdev ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_FROM_OVERLAY:
		fmt.Printf("Incoming packet from overlay ifindex %d\n", n.Arg1)
	case DBG_CAPTURE_DELIVERY:
		fmt.Printf("Delivery to ifindex %d\n", n.Arg1)
	default:
		fmt.Printf("Unknown message type=%d arg1=%d\n", n.SubType, n.Arg1)
	}
	Dissect(dissect, data[16:])
}
