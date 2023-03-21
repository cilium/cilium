// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
)

const (
	// DropNotifyLen is the amount of packet data provided in a drop notification
	DropNotifyLen = 36
)

// DropNotify is the message format of a drop notification in the BPF ring buffer
type DropNotify struct {
	Type     uint8
	SubType  uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint32
	SrcLabel identity.NumericIdentity
	DstLabel identity.NumericIdentity
	DstID    uint32
	Line     uint16
	File     uint8
	ExtError int8
	Ifindex  uint32
	// data
}

// dumpIdentity dumps the source and destination identities in numeric or
// human-readable format.
func (n *DropNotify) dumpIdentity(buf *bufio.Writer, numeric DisplayFormat) {
	if numeric {
		fmt.Fprintf(buf, ", identity %d->%d", n.SrcLabel, n.DstLabel)
	} else {
		fmt.Fprintf(buf, ", identity %s->%s", n.SrcLabel, n.DstLabel)
	}
}

var sourceFileNames = map[int]string{
	// source files from bpf/
	1: "bpf_host.c",
	2: "bpf_lxc.c",
	3: "bpf_overlay.c",
	4: "bpf_xdp.c",

	// header files from bpf/lib/
	101: "arp.h",
	102: "drop.h",
	103: "egress_policies.h",
	104: "icmp6.h",
	105: "nodeport.h",
	//end
}

func decodeBPFSourceFileName(fileId int) string {
	if name, ok := sourceFileNames[fileId]; ok {
		return name
	}
	// this shouldn't ever happen
	return fmt.Sprintf("<unknown-id-%d>", fileId)
}

// DumpInfo prints a summary of the drop messages.
func (n *DropNotify) DumpInfo(data []byte, numeric DisplayFormat) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "xx drop (%s) flow %#x to endpoint %d, ifindex %d, file %s:%d, ",
		api.DropReasonExt(n.SubType, n.ExtError), n.Hash, n.DstID, n.Ifindex, decodeBPFSourceFileName(int(n.File)), int(n.Line))
	n.dumpIdentity(buf, numeric)
	fmt.Fprintf(buf, ": %s\n", GetConnectionSummary(data[DropNotifyLen:]))
	buf.Flush()
}

// DumpVerbose prints the drop notification in human readable form
func (n *DropNotify) DumpVerbose(dissect bool, data []byte, prefix string, numeric DisplayFormat) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "%s MARK %#x FROM %d DROP: %d bytes, reason %s",
		prefix, n.Hash, n.Source, n.OrigLen, api.DropReasonExt(n.SubType, n.ExtError))

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		n.dumpIdentity(buf, numeric)
	}

	if n.DstID != 0 {
		fmt.Fprintf(buf, ", to endpoint %d\n", n.DstID)
	} else {
		fmt.Fprintf(buf, "\n")
	}

	if n.CapLen > 0 && len(data) > DropNotifyLen {
		Dissect(dissect, data[DropNotifyLen:])
	}
	buf.Flush()
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
	Reason    string `json:"reason,omitempty"`

	Source   uint16                   `json:"source"`
	Bytes    uint32                   `json:"bytes"`
	SrcLabel identity.NumericIdentity `json:"srcLabel"`
	DstLabel identity.NumericIdentity `json:"dstLabel"`
	DstID    uint32                   `json:"dstID"`
	Line     uint16                   `json:"Line"`
	File     uint8                    `json:"File"`
	ExtError int8                     `json:"ExtError"`
	Ifindex  uint32                   `json:"Ifindex"`

	Summary *DissectSummary `json:"summary,omitempty"`
}

// DropNotifyToVerbose creates verbose notification from DropNotify
func DropNotifyToVerbose(n *DropNotify) DropNotifyVerbose {
	return DropNotifyVerbose{
		Type:     "drop",
		Mark:     fmt.Sprintf("%#x", n.Hash),
		Reason:   api.DropReasonExt(n.SubType, n.ExtError),
		Source:   n.Source,
		Bytes:    n.OrigLen,
		SrcLabel: n.SrcLabel,
		DstLabel: n.DstLabel,
		DstID:    n.DstID,
		Line:     n.Line,
		File:     n.File,
		ExtError: n.ExtError,
		Ifindex:  n.Ifindex,
	}
}
