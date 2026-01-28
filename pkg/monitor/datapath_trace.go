// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// traceNotifyV0Len is the amount of packet data provided in a trace notification v0.
	traceNotifyV0Len = 32
	// traceNotifyV1Len is the amount of packet data provided in a trace notification v1.
	traceNotifyV1Len = 48
	// traceNotifyV2Len is the amount of packet data provided in a trace notification v2.
	traceNotifyV2Len = 56
)

const (
	// TraceNotifyFlagIsIPv6 is set in TraceNotify.Flags when the
	// notification refers to an IPv6 flow
	TraceNotifyFlagIsIPv6 uint8 = 1 << iota
	// TraceNotifyFlagIsL3Device is set in TraceNotify.Flags when the
	// notification refers to a L3 device.
	TraceNotifyFlagIsL3Device
	// TraceNotifyFlagIsVXLAN is set in TraceNotify.Flags when the
	// notification refers to an overlay VXLAN packet.
	TraceNotifyFlagIsVXLAN
	// TraceNotifyFlagIsGeneve is set in TraceNotify.Flags when the
	// notification refers to an overlay Geneve packet.
	TraceNotifyFlagIsGeneve
)

const (
	TraceNotifyVersion0 = iota
	TraceNotifyVersion1
	TraceNotifyVersion2
)

// TraceNotify is the message format of a trace notification in the BPF ring buffer
type TraceNotify struct {
	Type       uint8                    `align:"type"`
	ObsPoint   uint8                    `align:"subtype"`
	Source     uint16                   `align:"source"`
	Hash       uint32                   `align:"hash"`
	OrigLen    uint32                   `align:"len_orig"`
	CapLen     uint16                   `align:"len_cap"`
	Version    uint8                    `align:"version"`
	ExtVersion uint8                    `align:"ext_version"`
	SrcLabel   identity.NumericIdentity `align:"src_label"`
	DstLabel   identity.NumericIdentity `align:"dst_label"`
	DstID      uint16                   `align:"dst_id"`
	Reason     uint8                    `align:"reason"`
	Flags      uint8                    `align:"flags"`
	Ifindex    uint32                   `align:"ifindex"`
	OrigIP     types.IPv6               `align:"$union0"`
	IPTraceID  uint64                   `align:"ip_trace_id"`
	// data
}

// Dump prints the message according to the verbosity level specified
func (tn *TraceNotify) Dump(args *api.DumpArgs) {
	switch args.Verbosity {
	case api.INFO, api.DEBUG:
		tn.DumpInfo(args.Buf, args.Data, args.Format, args.LinkMonitor)
	case api.JSON:
		tn.DumpJSON(args.Buf, args.Data, args.CpuPrefix, args.LinkMonitor)
	default:
		fmt.Fprintln(args.Buf, msgSeparator)
		tn.DumpVerbose(args.Buf, args.Dissect, args.Data, args.CpuPrefix, args.Format, args.LinkMonitor)
	}
}

// GetSrc retrieves the source endpoint for the message.
func (tn *TraceNotify) GetSrc() uint16 {
	return tn.Source
}

// GetDst retrieves the destination endpoint or proxy destination port according to the message subtype.
func (tn *TraceNotify) GetDst() uint16 {
	return tn.DstID
}

// Decode decodes the message in 'data' into the struct.
func (tn *TraceNotify) Decode(data []byte) error {
	if l := len(data); l < traceNotifyV0Len {
		return fmt.Errorf("unexpected TraceNotify data length, expected at least %d but got %d", traceNotifyV0Len, l)
	}

	version := data[14]

	// Check against max version.
	if version > TraceNotifyVersion2 {
		return fmt.Errorf("Unrecognized trace event (version %d)", version)
	}

	// Decode logic for version >= v1.
	switch version {
	case TraceNotifyVersion2:
		if l := len(data); l < traceNotifyV2Len {
			return fmt.Errorf("unexpected TraceNotify data length (version %d), expected at least %d but got %d", version, traceNotifyV2Len, l)
		}
		tn.IPTraceID = binary.NativeEndian.Uint64(data[48:56])
		fallthrough
	case TraceNotifyVersion1:
		if l := len(data); l < traceNotifyV1Len {
			return fmt.Errorf("unexpected TraceNotify data length (version %d), expected at least %d but got %d", version, traceNotifyV1Len, l)
		}
		copy(tn.OrigIP[:], data[32:48])
	}

	// Decode logic for version >= v0.
	tn.Type = data[0]
	tn.ObsPoint = data[1]
	tn.Source = binary.NativeEndian.Uint16(data[2:4])
	tn.Hash = binary.NativeEndian.Uint32(data[4:8])
	tn.OrigLen = binary.NativeEndian.Uint32(data[8:12])
	tn.CapLen = binary.NativeEndian.Uint16(data[12:14])
	tn.Version = version
	tn.ExtVersion = data[15]
	tn.SrcLabel = identity.NumericIdentity(binary.NativeEndian.Uint32(data[16:20]))
	tn.DstLabel = identity.NumericIdentity(binary.NativeEndian.Uint32(data[20:24]))
	tn.DstID = binary.NativeEndian.Uint16(data[24:26])
	tn.Reason = data[26]
	tn.Flags = data[27]
	tn.Ifindex = binary.NativeEndian.Uint32(data[28:32])

	return nil
}

// IsEncrypted returns true when the notification has the encrypt flag set,
// false otherwise.
func (n *TraceNotify) IsEncrypted() bool {
	return (n.Reason & TraceReasonEncryptMask) != 0
}

// TraceReason returns the trace reason for this notification, see the
// TraceReason* constants.
func (n *TraceNotify) TraceReason() uint8 {
	return n.Reason & ^TraceReasonEncryptMask
}

// TraceReasonIsKnown returns false when the trace reason is unknown, true
// otherwise.
func (n *TraceNotify) TraceReasonIsKnown() bool {
	return n.TraceReason() != TraceReasonUnknown
}

// TraceReasonIsReply returns true when the trace reason is TraceReasonCtReply,
// false otherwise.
func (n *TraceNotify) TraceReasonIsReply() bool {
	return n.TraceReason() == TraceReasonCtReply
}

// TraceReasonIsEncap returns true when the trace reason is encapsulation
// related, false otherwise.
func (n *TraceNotify) TraceReasonIsEncap() bool {
	switch n.TraceReason() {
	case TraceReasonSRv6Encap:
		return true
	}
	return false
}

// TraceReasonIsDecap returns true when the trace reason is decapsulation
// related, false otherwise.
func (n *TraceNotify) TraceReasonIsDecap() bool {
	switch n.TraceReason() {
	case TraceReasonSRv6Decap:
		return true
	}
	return false
}

var (
	traceNotifyLength = map[uint8]uint{
		TraceNotifyVersion0: traceNotifyV0Len,
		TraceNotifyVersion1: traceNotifyV1Len,
		TraceNotifyVersion2: traceNotifyV2Len,
	}
)

const TraceNotifyExtensionDisabled = 0

var (
	// Downstream projects should register introduced extensions length so that
	// the upstream parsing code still works even if the DP events contain
	// additional fields.
	traceNotifyExtensionLengthFromVersion = map[uint8]uint{
		// The TraceNotifyExtension is intended for downstream extensions and
		// should not be used in the upstream project.
		TraceNotifyExtensionDisabled: 0,
	}
)

/* Reasons for forwarding a packet, keep in sync with api/v1/flow/flow.proto */
const (
	TraceReasonPolicy = iota
	TraceReasonCtEstablished
	TraceReasonCtReply
	TraceReasonCtRelated
	TraceReasonCtDeprecatedReopened
	TraceReasonUnknown
	TraceReasonSRv6Encap
	TraceReasonSRv6Decap
	TraceReasonDeprecatedEncryptOverlay
	// TraceReasonEncryptMask is the bit used to indicate encryption or not.
	TraceReasonEncryptMask = uint8(0x80)
)

/* keep in sync with api/v1/flow/flow.proto */
var traceReasons = map[uint8]string{
	TraceReasonPolicy:                   "new",
	TraceReasonCtEstablished:            "established",
	TraceReasonCtReply:                  "reply",
	TraceReasonCtRelated:                "related",
	TraceReasonCtDeprecatedReopened:     "reopened",
	TraceReasonUnknown:                  "unknown",
	TraceReasonSRv6Encap:                "srv6-encap",
	TraceReasonSRv6Decap:                "srv6-decap",
	TraceReasonDeprecatedEncryptOverlay: "encrypt-overlay",
}

// dumpIdentity dumps the source and destination identities in numeric or
// human-readable format.
func (n *TraceNotify) dumpIdentity(buf *bufio.Writer, numeric api.DisplayFormat) {
	if numeric {
		fmt.Fprintf(buf, ", identity %d->%d", n.SrcLabel, n.DstLabel)
	} else {
		fmt.Fprintf(buf, ", identity %s->%s", n.SrcLabel, n.DstLabel)
	}
}

func (n *TraceNotify) encryptReasonString() string {
	if n.IsEncrypted() {
		return "encrypted "
	}
	return ""
}

func (n *TraceNotify) traceReasonString() string {
	if str, ok := traceReasons[n.TraceReason()]; ok {
		return str
	}
	// NOTE: show the underlying datapath trace reason without excluding the
	// encrypt mask.
	return fmt.Sprintf("%d", n.Reason)
}

func (n *TraceNotify) traceSummary() string {
	switch n.ObsPoint {
	case api.TraceToLxc:
		return fmt.Sprintf("-> endpoint %d", n.DstID)
	case api.TraceToProxy:
		pp := ""
		if n.DstID != 0 {
			pp = fmt.Sprintf(" port %d", n.DstID)
		}
		return "-> proxy" + pp
	case api.TraceToHost:
		return "-> host from"
	case api.TraceToStack:
		return "-> stack"
	case api.TraceToOverlay:
		return "-> overlay"
	case api.TraceToNetwork:
		return "-> network"
	case api.TraceFromLxc:
		return fmt.Sprintf("<- endpoint %d", n.Source)
	case api.TraceFromProxy:
		return "<- proxy"
	case api.TraceFromHost:
		return "<- host"
	case api.TraceFromStack:
		return "<- stack"
	case api.TraceFromOverlay:
		return "<- overlay"
	case api.TraceFromNetwork:
		return "<- network"
	case api.TraceFromCrypto:
		return "<- crypto"
	case api.TraceToCrypto:
		return "-> crypto"
	default:
		return "unknown trace"
	}
}

// IsL3Device returns true if the trace comes from an L3 device.
func (n *TraceNotify) IsL3Device() bool {
	return n.Flags&TraceNotifyFlagIsL3Device != 0
}

// IsIPv6 returns true if the trace refers to an IPv6 packet.
func (n *TraceNotify) IsIPv6() bool {
	return n.Flags&TraceNotifyFlagIsIPv6 != 0
}

// IsVXLAN returns true if the trace refers to an overlay VXLAN packet.
func (n *TraceNotify) IsVXLAN() bool {
	return n.Flags&TraceNotifyFlagIsVXLAN != 0
}

// IsGeneve returns true if the trace refers to an overlay Geneve packet.
func (n *TraceNotify) IsGeneve() bool {
	return n.Flags&TraceNotifyFlagIsGeneve != 0
}

// OriginalIP returns the original source IP if reverse NAT was performed on
// the flow
func (n *TraceNotify) OriginalIP() net.IP {
	if n.IsIPv6() {
		return n.OrigIP[:]
	}
	return n.OrigIP[:4]
}

// DataOffset returns the offset from the beginning of TraceNotify where the
// trace notify data begins.
//
// Returns zero for invalid or unknown TraceNotify messages.
func (n *TraceNotify) DataOffset() uint {
	return traceNotifyLength[n.Version] + traceNotifyExtensionLengthFromVersion[n.ExtVersion]
}

// DumpInfo prints a summary of the trace messages.
func (n *TraceNotify) DumpInfo(buf *bufio.Writer, data []byte, numeric api.DisplayFormat, linkMonitor getters.LinkGetter) {
	hdrLen := n.DataOffset()
	if enc := n.encryptReasonString(); enc != "" {
		fmt.Fprintf(buf, "%s %s flow %#x ",
			n.traceSummary(), enc, n.Hash)
	} else {
		fmt.Fprintf(buf, "%s flow %#x ", n.traceSummary(), n.Hash)
	}
	n.dumpIdentity(buf, numeric)
	ifname := linkMonitor.Name(n.Ifindex)

	if id := n.IPTraceID; id > 0 {
		fmt.Fprintf(buf, " [ ip-trace-id = %d ]", id)
	}
	fmt.Fprintf(buf, " state %s ifindex %s orig-ip %s: %s\n",
		n.traceReasonString(), ifname, n.OriginalIP().String(), GetConnectionSummary(data[hdrLen:], &decodeOpts{n.IsL3Device(), n.IsIPv6(), n.IsVXLAN(), n.IsGeneve()}))
	buf.Flush()
}

// DumpVerbose prints the trace notification in human readable form
func (n *TraceNotify) DumpVerbose(buf *bufio.Writer, dissect bool, data []byte, prefix string, numeric api.DisplayFormat, linkMonitor getters.LinkGetter) {
	fmt.Fprintf(buf, "%s MARK %#x", prefix, n.Hash)
	if id := n.IPTraceID; id > 0 {
		fmt.Fprintf(buf, " [ IP-TRACE-ID = %d ]", id)
	}
	fmt.Fprintf(buf, " FROM %d %s: %d bytes (%d captured), state %s",
		n.Source, api.TraceObservationPoint(n.ObsPoint), n.OrigLen, n.CapLen, n.traceReasonString())

	if n.Ifindex != 0 {
		ifname := linkMonitor.Name(n.Ifindex)
		fmt.Fprintf(buf, ", interface %s", ifname)
	}

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		fmt.Fprintf(buf, ", ")
		n.dumpIdentity(buf, numeric)
	}

	fmt.Fprintf(buf, ", orig-ip %s", n.OriginalIP().String())

	if n.DstID != 0 {
		dst := "endpoint"
		if n.ObsPoint == api.TraceToProxy {
			dst = "proxy-port"
		}
		fmt.Fprintf(buf, ", to %s %d\n", dst, n.DstID)
	} else {
		fmt.Fprintf(buf, "\n")
	}

	hdrLen := n.DataOffset()
	if n.CapLen > 0 && len(data) > int(hdrLen) {
		Dissect(buf, dissect, data[hdrLen:], &decodeOpts{n.IsL3Device(), n.IsIPv6(), n.IsVXLAN(), n.IsGeneve()})
	}
}

func (n *TraceNotify) getJSON(data []byte, cpuPrefix string, linkMonitor getters.LinkGetter) (string, error) {
	v := TraceNotifyToVerbose(n, linkMonitor)
	v.CPUPrefix = cpuPrefix
	hdrLen := n.DataOffset()
	if n.CapLen > 0 && len(data) > int(hdrLen) {
		v.Summary = GetDissectSummary(data[hdrLen:], &decodeOpts{n.IsL3Device(), n.IsIPv6(), n.IsVXLAN(), n.IsGeneve()})
	}

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (n *TraceNotify) DumpJSON(buf *bufio.Writer, data []byte, cpuPrefix string, linkMonitor getters.LinkGetter) {
	resp, err := n.getJSON(data, cpuPrefix, linkMonitor)
	if err == nil {
		fmt.Fprintln(buf, resp)
	}
}

// TraceNotifyVerbose represents a json notification printed by monitor
type TraceNotifyVerbose struct {
	CPUPrefix        string `json:"cpu,omitempty"`
	Type             string `json:"type,omitempty"`
	Mark             string `json:"mark,omitempty"`
	Ifindex          string `json:"ifindex,omitempty"`
	State            string `json:"state,omitempty"`
	ObservationPoint string `json:"observationPoint"`
	TraceSummary     string `json:"traceSummary"`

	Source    uint16                   `json:"source"`
	Bytes     uint32                   `json:"bytes"`
	SrcLabel  identity.NumericIdentity `json:"srcLabel"`
	DstLabel  identity.NumericIdentity `json:"dstLabel"`
	DstID     uint16                   `json:"dstID"`
	IPTraceID uint64                   `json:"IpTraceID"`

	Summary *DissectSummary `json:"summary,omitempty"`
}

// TraceNotifyToVerbose creates verbose notification from base TraceNotify
func TraceNotifyToVerbose(n *TraceNotify, linkMonitor getters.LinkGetter) TraceNotifyVerbose {
	ifname := linkMonitor.Name(n.Ifindex)
	return TraceNotifyVerbose{
		Type:             "trace",
		Mark:             fmt.Sprintf("%#x", n.Hash),
		Ifindex:          ifname,
		State:            n.traceReasonString(),
		ObservationPoint: api.TraceObservationPoint(n.ObsPoint),
		TraceSummary:     n.traceSummary(),
		Source:           n.Source,
		Bytes:            n.OrigLen,
		SrcLabel:         n.SrcLabel,
		DstLabel:         n.DstLabel,
		DstID:            n.DstID,
		IPTraceID:        n.IPTraceID,
	}
}
