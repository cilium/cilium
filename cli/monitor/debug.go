package monitor

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
	DBG_NO_POLICY
	DBG_POLICY_DENIED
	DBG_CT_LOOKUP
	DBG_CT_MATCH
	DBG_CT_CREATED
	DBG_ICMP6_REQUEST
	DBG_ICMP6_NS
	DBG_ICMP6_TIME_EXCEEDED
)

type DebugMsg struct {
	Type    uint8
	SubType uint8
	Flags   uint16
	Arg1    uint32
	Arg2    uint32
}

func (n *DebugMsg) Dump(data []byte) {
	fmt.Printf("DEBUG: ")
	switch n.SubType {
	case DBG_GENERIC:
		fmt.Printf("No message, arg1=%d (%#x) arg2=%d (%#x)\n", n.Arg1, n.Arg1, n.Arg2, n.Arg2)
	case DBG_LOCAL_DELIVERY:
		fmt.Printf("Attempting local delivery for container id %d from seclabel %d\n", n.Arg1, n.Arg2)
	case DBG_ENCAP:
		fmt.Printf("Encapsulating to node %d (%#x) from seclabel %d\n", n.Arg1, n.Arg1, n.Arg2)
	case DBG_LXC_FOUND:
		fmt.Printf("Local container found ifindex %d seclabel %d\n", n.Arg1, n.Arg2)
	case DBG_NO_POLICY:
		fmt.Printf("No policy program found for id %d (FIXME: resolve), dropping...\n", n.Arg1)
	case DBG_POLICY_DENIED:
		fmt.Printf("Policy denied from %d to %d\n", n.Arg1, n.Arg2)
	case DBG_CT_LOOKUP:
		fmt.Printf("CT lookup sport=%d dport=%d\n", n.Arg1, n.Arg2)
	case DBG_CT_MATCH:
		fmt.Printf("CT entry found flags=%#x IPv6=[...]:%x\n", n.Arg1, n.Arg2)
	case DBG_CT_CREATED:
		fmt.Printf("CT created proto=%d flags=%#x\n", n.Arg1, n.Arg2)
	case DBG_ICMP6_REQUEST:
		fmt.Printf("ICMPv6 echo request for router offset=%d\n", n.Arg1)
	case DBG_ICMP6_NS:
		fmt.Printf("ICMPv6 neighbour soliciation for address %x:%x\n", n.Arg1, n.Arg2)
	case DBG_ICMP6_TIME_EXCEEDED:
		fmt.Printf("Sending ICMPv6 time exceeded\n")
	default:
		fmt.Printf("Unknown message type=%d arg1=%d arg2=%d\n", n.SubType, n.Arg1, n.Arg2)
	}
}

type DebugCapture struct {
	Type    uint8
	SubType uint8
	Flags   uint16
	Len     uint32
	Arg1    uint32
	// data
}

func (n *DebugCapture) Dump(dissect bool, data []byte) {
	fmt.Printf("DEBUG: %d bytes ", n.Len)
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
	Dissect(dissect, data[12:])
}
