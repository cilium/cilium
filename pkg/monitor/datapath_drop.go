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

package monitor

import (
	"encoding/json"
	"fmt"
)

const (
	// DropNotifyLen is the amount of packet data provided in a drop notification
	DropNotifyLen = 32
)

// DropNotify is the message format of a drop notification in the BPF ring buffer
type DropNotify struct {
	Type     uint8
	SubType  uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint32
	SrcLabel uint32
	DstLabel uint32
	DstID    uint32
	Ifindex  uint32
	// data
}

var errors = map[uint8]string{
	0:   "Success",
	2:   "Invalid packet",
	130: "Invalid source mac",
	131: "Invalid destination mac",
	132: "Invalid source ip",
	133: "Policy denied (L3)",
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
	156: "Invalid IPv6 extension header",
	157: "IP fragmentation not supported",
	158: "Service backend not found",
	159: "Policy denied (L4)",
	160: "No tunnel/encapsulation endpoint (datapath BUG!)",
	161: "Failed to insert into proxymap",
	162: "Policy denied (CIDR)",
	163: "Unknown connection tracking state",
	164: "Local host is unreachable",
	165: "No configuration available to perform policy decision",
}

// DropReason prints the drop reason in a human readable string
func DropReason(reason uint8) string {
	if err, ok := errors[reason]; ok {
		return err
	}
	return fmt.Sprintf("%d", reason)
}

// DumpInfo prints a summary of the drop messages.
func (n *DropNotify) DumpInfo(data []byte) {
	fmt.Printf("xx drop (%s) flow %#x to endpoint %d, identity %d->%d: %s\n",
		DropReason(n.SubType), n.Hash, n.DstID, n.SrcLabel, n.DstLabel,
		GetConnectionSummary(data[DropNotifyLen:]))
}

// DumpVerbose prints the drop notification in human readable form
func (n *DropNotify) DumpVerbose(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d DROP: %d bytes, reason %s, to ifindex %s",
		prefix, n.Hash, n.Source, n.OrigLen, DropReason(n.SubType), ifname(int(n.Ifindex)))

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		fmt.Printf(", identity %d->%d", n.SrcLabel, n.DstLabel)
	}

	if n.DstID != 0 {
		fmt.Printf(", to endpoint %d\n", n.DstID)
	} else {
		fmt.Printf("\n")
	}

	if n.CapLen > 0 && len(data) > DropNotifyLen {
		Dissect(dissect, data[DropNotifyLen:])
	}
}

func (n *DropNotify) getJSON(data []byte, cpuPrefix string) (string, error) {

	v := DropNotifyToVerbose(n)
	v.CPUPrefix = cpuPrefix
	if n.CapLen > 0 && len(data) > DropNotifyLen {
		v.Summary = GetDissectSummary(data[DropNotifyLen:])
	}

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (n *DropNotify) DumpJSON(data []byte, cpuPrefix string) {
	resp, err := n.getJSON(data, cpuPrefix)
	if err == nil {
		fmt.Println(resp)
	}
}

// DropNotifyVerbose represents a json notification printed by monitor
type DropNotifyVerbose struct {
	CPUPrefix string `json:"cpu,omitempty"`
	Type      string `json:"type,omitempty"`
	Mark      string `json:"mark,omitempty"`
	Ifindex   string `json:"ifindex,omitempty"`
	Reason    string `json:"reason,omitempty"`

	Source   uint16 `json:"source"`
	Bytes    uint32 `json:"bytes"`
	SrcLabel uint32 `json:"srcLabel"`
	DstLabel uint32 `json:"dstLabel"`
	DstID    uint32 `json:"dstID"`

	Summary *DissectSummary `json:"summary,omitempty"`
}

//DropNotifyToVerbose creates verbose notification from DropNotify
func DropNotifyToVerbose(n *DropNotify) DropNotifyVerbose {
	return DropNotifyVerbose{
		Type:     "drop",
		Mark:     fmt.Sprintf("%#x", n.Hash),
		Ifindex:  ifname(int(n.Ifindex)),
		Reason:   DropReason(n.SubType),
		Source:   n.Source,
		Bytes:    n.OrigLen,
		SrcLabel: n.SrcLabel,
		DstLabel: n.DstLabel,
		DstID:    n.DstID,
	}
}
