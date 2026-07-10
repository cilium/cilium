// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
)

const (
	DropNotifyVersion0 = iota
	DropNotifyVersion1
	DropNotifyVersion2
	DropNotifyVersion3
)

const (
	// dropNotifyV1Len is the amount of packet data provided in a v0/v1 drop notification.
	dropNotifyV1Len = 36
	// dropNotifyV2Len is the amount of packet data provided in a v2 drop notification.
	dropNotifyV2Len = 40
	// dropNotifyV3Len is the amount of packet data provided in a v3 drop notification.
	dropNotifyV3Len = 48
)

const (
	// DropNotifyFlagIsIPv6 is set in DropNotify.Flags when it refers to an IPv6 flow.
	DropNotifyFlagIsIPv6 uint8 = 1 << iota
	// DropNotifyFlagIsL3Device is set in DropNotify.Flags when it refers to a L3 device.
	DropNotifyFlagIsL3Device
	// DropNotifyFlagIsVXLAN is set in DropNotify.Flags when it refers to an overlay VXLAN packet.
	DropNotifyFlagIsVXLAN
	// DropNotifyFlagIsGeneve is set in DropNotify.Flags when it refers to an overlay Geneve packet.
	DropNotifyFlagIsGeneve
)

var (
	dropNotifyLengthFromVersion = map[uint8]uint{
		DropNotifyVersion0: dropNotifyV1Len, // retain backwards compatibility for testing.
		DropNotifyVersion1: dropNotifyV1Len,
		DropNotifyVersion2: dropNotifyV2Len,
		DropNotifyVersion3: dropNotifyV3Len,
	}
)

const DropNotifyExtensionDisabled = 0

var (
	// Downstream projects should register introduced extensions length so that
	// the upstream parsing code still works even if the DP events contain
	// additional fields.
	dropNotifyExtensionLengthFromVersion = map[uint8]uint{
		// The DropNotifyExtension is intended for downstream extensions and
		// should not be used in the upstream project.
		DropNotifyExtensionDisabled: 0,
	}
)

// DropNotify is the message format of a drop notification in the BPF ring buffer
type DropNotify struct {
	Type       uint8                    `align:"type"`
	SubType    uint8                    `align:"subtype"`
	Source     uint16                   `align:"source"`
	Hash       uint32                   `align:"hash"`
	OrigLen    uint32                   `align:"len_orig"`
	CapLen     uint16                   `align:"len_cap"`
	Version    uint8                    `align:"version"`
	ExtVersion uint8                    `align:"ext_version"`
	SrcLabel   identity.NumericIdentity `align:"src_label"`
	DstLabel   identity.NumericIdentity `align:"dst_label"`
	DstID      uint32                   `align:"dst_id"`
	Line       uint16                   `align:"line"`
	File       uint8                    `align:"file"`
	ExtError   int8                     `align:"ext_error"`
	Ifindex    uint32                   `align:"ifindex"`
	Flags      uint8                    `align:"flags"`
	_          [3]uint8                 `align:"pad2"`
	IPTraceID  uint64                   `align:"ip_trace_id"`
	// data
}

// Dump prints the message according to the verbosity level specified
func (dn *DropNotify) Dump(args *api.DumpArgs) {
	switch args.Verbosity {
	case api.INFO, api.DEBUG:
		dn.DumpInfo(args.Buf, args.Data, args.Format)
	case api.JSON:
		dn.DumpJSON(args.Buf, args.Data, args.CpuPrefix)
	default:
		fmt.Fprintln(args.Buf, msgSeparator)
		dn.DumpVerbose(args.Buf, !args.Dissect, args.Data, args.CpuPrefix, args.Format)
	}
}

// GetSrc retrieves the source endpoint for the message.
func (n *DropNotify) GetSrc() uint16 {
	return n.Source
}

// GetDst retrieves the destination endpoint for the message.
func (n *DropNotify) GetDst() uint16 {
	return uint16(n.DstID)
}

// dumpIdentity dumps the source and destination identities in numeric or
// human-readable format.
func (n *DropNotify) dumpIdentity(buf *bufio.Writer, numeric api.DisplayFormat) {
	if numeric {
		fmt.Fprintf(buf, ", identity %d->%d", n.SrcLabel, n.DstLabel)
	} else {
		fmt.Fprintf(buf, ", identity %s->%s", n.SrcLabel, n.DstLabel)
	}
}

// Decode decodes the message in 'data' into the struct.
func (n *DropNotify) Decode(data []byte) error {
	if l := len(data); l < dropNotifyV1Len {
		return fmt.Errorf("unexpected DropNotify data length, expected at least %d but got %d", dropNotifyV1Len, l)
	}

	version := data[14]

	// Check against max version.
	if version > DropNotifyVersion3 {
		return fmt.Errorf("Unrecognized drop event (version %d)", version)
	}

	// Decode logic for version >= v2.
	if version >= DropNotifyVersion2 {
		if l := len(data); l < dropNotifyV2Len {
			return fmt.Errorf("unexpected DropNotify data length (version %d), expected at least %d but got %d", version, dropNotifyV2Len, l)
		}
		n.Flags = data[36]
	}

	if version >= DropNotifyVersion3 {
		if l := len(data); l < dropNotifyV3Len {
			return fmt.Errorf("unexpected DropNotify data length (version %d), expected at least %d but got %d", version, dropNotifyV3Len, l)
		}
		n.IPTraceID = binary.NativeEndian.Uint64(data[40:48])
	}

	// Decode logic for version >= v0/v1.
	n.Type = data[0]
	n.SubType = data[1]
	n.Source = binary.NativeEndian.Uint16(data[2:4])
	n.Hash = binary.NativeEndian.Uint32(data[4:8])
	n.OrigLen = binary.NativeEndian.Uint32(data[8:12])
	n.CapLen = binary.NativeEndian.Uint16(data[12:14])
	n.Version = version
	n.ExtVersion = data[15]
	n.SrcLabel = identity.NumericIdentity(binary.NativeEndian.Uint32(data[16:20]))
	n.DstLabel = identity.NumericIdentity(binary.NativeEndian.Uint32(data[20:24]))
	n.DstID = binary.NativeEndian.Uint32(data[24:28])
	n.Line = binary.NativeEndian.Uint16(data[28:30])
	n.File = data[30]
	n.ExtError = int8(data[31])
	n.Ifindex = binary.NativeEndian.Uint32(data[32:36])

	return nil
}

// IsL3Device returns true if the trace comes from an L3 device.
func (n *DropNotify) IsL3Device() bool {
	return n.Flags&DropNotifyFlagIsL3Device != 0
}

// IsIPv6 returns true if the trace refers to an IPv6 packet.
func (n *DropNotify) IsIPv6() bool {
	return n.Flags&DropNotifyFlagIsIPv6 != 0
}

// IsGeneve returns true if the trace refers to an overlay Geneve packet.
func (n *DropNotify) IsGeneve() bool {
	return n.Flags&DropNotifyFlagIsGeneve != 0
}

// IsVXLAN returns true if the trace refers to an overlay VXLAN packet.
func (n *DropNotify) IsVXLAN() bool {
	return n.Flags&DropNotifyFlagIsVXLAN != 0
}

// DataOffset returns the offset from the beginning of DropNotify where the
// notification data begins.
//
// Returns zero for invalid or unknown DropNotify messages.
func (n *DropNotify) DataOffset() uint {
	return dropNotifyLengthFromVersion[n.Version] + dropNotifyExtensionLengthFromVersion[n.ExtVersion]
}

// DumpInfo prints a summary of the drop messages.
func (n *DropNotify) DumpInfo(buf *bufio.Writer, data []byte, numeric api.DisplayFormat) {
	fmt.Fprintf(buf, "xx drop (%s) flow %#x to endpoint %d, ifindex %d, file %s:%d, ",
		api.DropReasonExt(n.SubType, n.ExtError), n.Hash, n.DstID, n.Ifindex, api.BPFFileName(n.File), int(n.Line))
	if id := n.IPTraceID; id > 0 {
		fmt.Fprintf(buf, " [ ip-trace-id = %d ]", id)
	}
	n.dumpIdentity(buf, numeric)
	fmt.Fprintf(buf, ": %s\n", GetConnectionSummary(data[n.DataOffset():], &decodeOpts{n.IsL3Device(), n.IsIPv6(), n.IsVXLAN(), n.IsGeneve()}))
}

// DumpVerbose prints the drop notification in human readable form
func (n *DropNotify) DumpVerbose(buf *bufio.Writer, dissect bool, data []byte, prefix string, numeric api.DisplayFormat) {
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

	if id := n.IPTraceID; id > 0 {
		fmt.Fprintf(buf, " [ IP-TRACE-ID=%d", id)
	}

	if offset := int(n.DataOffset()); n.CapLen > 0 && len(data) > offset {
		Dissect(buf, dissect, data[offset:], &decodeOpts{n.IsL3Device(), n.IsIPv6(), n.IsVXLAN(), n.IsGeneve()})
	}
}

func (n *DropNotify) getJSON(data []byte, cpuPrefix string) (string, error) {
	v := DropNotifyToVerbose(n)
	v.CPUPrefix = cpuPrefix
	if offset := int(n.DataOffset()); n.CapLen > 0 && len(data) > offset {
		v.Summary = GetDissectSummary(data[offset:], &decodeOpts{n.IsL3Device(), n.IsIPv6(), n.IsVXLAN(), n.IsGeneve()})
	}

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (n *DropNotify) DumpJSON(buf *bufio.Writer, data []byte, cpuPrefix string) {
	resp, err := n.getJSON(data, cpuPrefix)
	if err == nil {
		fmt.Fprintln(buf, resp)
	}
}

// DropNotifyVerbose represents a json notification printed by monitor
type DropNotifyVerbose struct {
	CPUPrefix string `json:"cpu,omitempty"`
	Type      string `json:"type,omitempty"`
	Mark      string `json:"mark,omitempty"`
	Reason    string `json:"reason,omitempty"`

	Source    uint16                   `json:"source"`
	Bytes     uint32                   `json:"bytes"`
	SrcLabel  identity.NumericIdentity `json:"srcLabel"`
	DstLabel  identity.NumericIdentity `json:"dstLabel"`
	DstID     uint32                   `json:"dstID"`
	Line      uint16                   `json:"Line"`
	File      uint8                    `json:"File"`
	ExtError  int8                     `json:"ExtError"`
	Ifindex   uint32                   `json:"Ifindex"`
	IPTraceID uint64                   `json:"IPTraceID,omitempty"`

	Summary *DissectSummary `json:"summary,omitempty"`
}

// DropNotifyToVerbose creates verbose notification from DropNotify
func DropNotifyToVerbose(n *DropNotify) DropNotifyVerbose {
	return DropNotifyVerbose{
		Type:      "drop",
		Mark:      fmt.Sprintf("%#x", n.Hash),
		Reason:    api.DropReasonExt(n.SubType, n.ExtError),
		Source:    n.Source,
		Bytes:     n.OrigLen,
		SrcLabel:  n.SrcLabel,
		DstLabel:  n.DstLabel,
		DstID:     n.DstID,
		Line:      n.Line,
		File:      n.File,
		ExtError:  n.ExtError,
		Ifindex:   n.Ifindex,
		IPTraceID: n.IPTraceID,
	}
}
