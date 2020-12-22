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
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
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
	SrcLabel identity.NumericIdentity
	DstLabel identity.NumericIdentity
	DstID    uint32
	Unused   uint32
	// data
}

// dumpIdentity dumps the source and destination identities in numeric or
// human-readable format.
func (n *DropNotify) dumpIdentity(buf *bufio.Writer, numeric DisplayFormat) {
	if numeric {
		fmt.Fprintf(buf, "identity %d->%d", n.SrcLabel, n.DstLabel)
	} else {
		fmt.Fprintf(buf, "identity %s->%s", n.SrcLabel, n.DstLabel)
	}
}

// DumpInfo prints a summary of the drop messages.
func (n *DropNotify) DumpInfo(data []byte, numeric DisplayFormat) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "xx drop (%s) flow %#x to endpoint %d, ",
		api.DropReason(n.SubType), n.Hash, n.DstID)
	n.dumpIdentity(buf, numeric)
	fmt.Fprintf(buf, ": %s\n", GetConnectionSummary(data[DropNotifyLen:]))
	buf.Flush()
}

// DumpVerbose prints the drop notification in human readable form
func (n *DropNotify) DumpVerbose(dissect bool, data []byte, prefix string, numeric DisplayFormat) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "%s MARK %#x FROM %d DROP: %d bytes, reason %s",
		prefix, n.Hash, n.Source, n.OrigLen, api.DropReason(n.SubType))

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

	Summary *DissectSummary `json:"summary,omitempty"`
}

//DropNotifyToVerbose creates verbose notification from DropNotify
func DropNotifyToVerbose(n *DropNotify) DropNotifyVerbose {
	return DropNotifyVerbose{
		Type:     "drop",
		Mark:     fmt.Sprintf("%#x", n.Hash),
		Reason:   api.DropReason(n.SubType),
		Source:   n.Source,
		Bytes:    n.OrigLen,
		SrcLabel: n.SrcLabel,
		DstLabel: n.DstLabel,
		DstID:    n.DstID,
	}
}
