package bpf

import (
	"fmt"
)

type DropNotify struct {
	Type     uint8
	SubType  uint8
	Source   uint16
	OrigLen  uint32
	CapLen   uint32
	SrcLabel uint32
	DstLabel uint32
	DstID    uint32
	Ifindex  uint32
	// data
}

// Must be synchronized with <bpf/lib/common.h>
const (
	CILIUM_NOTIFY_UNSPEC = iota
	CILIUM_NOTIFY_DROP
	CILIUM_DBG_MSG
	CILIUM_DBG_CAPTURE
)

var errors = map[uint8]string{
	0:   "Success",
	2:   "Invalid packet",
	130: "Invalid source mac",
	131: "Invalid destination mac",
	132: "Invalid source ip",
	133: "Policy denied",
	134: "Invalid packet",
	135: "CT: Truncated or invalid header",
	136: "CT: Missing TCP ACK flag",
	137: "CT: Unknown L4 protocol",
	138: "CT: Can't create entry from packet",
	139: "Unsupported L3 protocol",
	140: "Missed tail call",
	141: "Error writing to packet",
	142: "Unknown L4 protocol",
	143: "Unknown ICMPv4 code",
	144: "Unknown ICMPv4 type",
	145: "Unknown ICMPv6 code",
	146: "Unknown ICMPv6 type",
	147: "Error retrieving tunnel key",
	148: "Error retrieving tunnel options",
	149: "Invalid Geneve option",
	150: "Unknown L3 target address",
	151: "Not a local target address",
	152: "No matching local container found",
	153: "Error while correcting L3 checksum",
	154: "Error while correcting L4 checksum",
	155: "CT: Map insertion failed",
}

func (n *DropNotify) Dump(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s FROM %d Packet dropped %d (%s) %d bytes ifindex=%d",
		prefix, n.Source, n.SubType, errors[n.SubType], n.OrigLen, n.Ifindex)

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		fmt.Printf(" %d->%d", n.SrcLabel, n.DstLabel)
	}

	if n.DstID != 0 {
		fmt.Printf(" to lxc %d\n", n.DstID)
	} else {
		fmt.Printf("\n")
	}

	Dissect(dissect, data[28:])
}
