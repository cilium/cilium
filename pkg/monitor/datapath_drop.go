// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
)

const (
	DropNotifyVersion0 = 0
	DropNotifyVersion1 = 1

	// DropNotifyV1Len is the amount of packet data provided in a v1 drop notification.
	DropNotifyV1Len = 36
)

var (
	dropNotifyLengthFromVersion = map[uint16]uint{
		DropNotifyVersion0: DropNotifyV1Len, // retain backwards compatibility for testing.
		DropNotifyVersion1: DropNotifyV1Len,
	}
)

// DropNotify is the message format of a drop notification in the BPF ring buffer
type DropNotify struct {
	Type     uint8
	SubType  uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint16
	Version  uint16
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

// DecodeDropNotify will decode 'data' into the provided DropNotify structure
func DecodeDropNotify(data []byte, dn *DropNotify) error {
	return dn.decodeDropNotify(data)
}

func (n *DropNotify) decodeDropNotify(data []byte) error {
	if l := len(data); l < DropNotifyV1Len {
		return fmt.Errorf("unexpected DropNotify data length, expected %d but got %d", DropNotifyV1Len, l)
	}

	n.Type = data[0]
	n.SubType = data[1]
	n.Source = byteorder.Native.Uint16(data[2:4])
	n.Hash = byteorder.Native.Uint32(data[4:8])
	n.OrigLen = byteorder.Native.Uint32(data[8:12])
	n.CapLen = byteorder.Native.Uint16(data[12:14])
	n.Version = byteorder.Native.Uint16(data[14:16])
	n.SrcLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[16:20]))
	n.DstLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[20:24]))
	n.DstID = byteorder.Native.Uint32(data[24:28])
	n.Line = byteorder.Native.Uint16(data[28:30])
	n.File = data[30]
	n.ExtError = int8(data[31])
	n.Ifindex = byteorder.Native.Uint32(data[32:36])

	return nil
}

// DataOffset returns the offset from the beginning of DropNotify where the
// notification data begins.
//
// Returns zero for invalid or unknown DropNotify messages.
func (n *DropNotify) DataOffset() uint {
	return dropNotifyLengthFromVersion[n.Version]
}

// DumpInfo prints a summary of the drop messages.
func (n *DropNotify) DumpInfo(data []byte, numeric DisplayFormat) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "xx drop (%s) flow %#x to endpoint %d, ifindex %d, file %s:%d, ",
		api.DropReasonExt(n.SubType, n.ExtError), n.Hash, n.DstID, n.Ifindex, api.BPFFileName(n.File), int(n.Line))
	n.dumpIdentity(buf, numeric)
	fmt.Fprintf(buf, ": %s\n", GetConnectionSummary(data[n.DataOffset():], nil))
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

	if offset := int(n.DataOffset()); n.CapLen > 0 && len(data) > offset {
		Dissect(dissect, data[offset:])
	}
	buf.Flush()
}

func (n *DropNotify) getJSON(data []byte, cpuPrefix string) (string, error) {

	v := DropNotifyToVerbose(n)
	v.CPUPrefix = cpuPrefix
	if offset := int(n.DataOffset()); n.CapLen > 0 && len(data) > offset {
		v.Summary = GetDissectSummary(data[offset:])
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
