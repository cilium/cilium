// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/byteorder"
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
)

const (
	// TraceNotifyFlagIsIPv6 is set in TraceNotify.Flags when the
	// notification refers to an IPv6 flow
	TraceNotifyFlagIsIPv6 uint8 = 1 << iota
	// TraceNotifyFlagIsL3Device is set in TraceNotify.Flags when the
	// notification refers to a L3 device.
	TraceNotifyFlagIsL3Device
)

const (
	TraceNotifyVersion0 = iota
	TraceNotifyVersion1
)

// TraceNotify is the message format of a trace notification in the BPF ring buffer
type TraceNotify struct {
	Type     uint8
	ObsPoint uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint16
	Version  uint16
	SrcLabel identity.NumericIdentity
	DstLabel identity.NumericIdentity
	DstID    uint16
	Reason   uint8
	Flags    uint8
	Ifindex  uint32
	OrigIP   types.IPv6
	// data
}

// decodeTraceNotify decodes the trace notify message in 'data' into the struct.
func (tn *TraceNotify) decodeTraceNotify(data []byte) error {
	if l := len(data); l < traceNotifyV0Len {
		return fmt.Errorf("unexpected TraceNotify data length, expected at least %d but got %d", traceNotifyV0Len, l)
	}

	version := byteorder.Native.Uint16(data[14:16])

	// Check against max version.
	if version > TraceNotifyVersion1 {
		return fmt.Errorf("Unrecognized trace event (version %d)", version)
	}

	// Decode logic for version >= v1.
	if version >= TraceNotifyVersion1 {
		if l := len(data); l < traceNotifyV1Len {
			return fmt.Errorf("unexpected TraceNotify data length (version %d), expected at least %d but got %d", version, traceNotifyV1Len, l)
		}
		copy(tn.OrigIP[:], data[32:48])
	}

	// Decode logic for version >= v0.
	tn.Type = data[0]
	tn.ObsPoint = data[1]
	tn.Source = byteorder.Native.Uint16(data[2:4])
	tn.Hash = byteorder.Native.Uint32(data[4:8])
	tn.OrigLen = byteorder.Native.Uint32(data[8:12])
	tn.CapLen = byteorder.Native.Uint16(data[12:14])
	tn.Version = version
	tn.SrcLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[16:20]))
	tn.DstLabel = identity.NumericIdentity(byteorder.Native.Uint32(data[20:24]))
	tn.DstID = byteorder.Native.Uint16(data[24:26])
	tn.Reason = data[26]
	tn.Flags = data[27]
	tn.Ifindex = byteorder.Native.Uint32(data[28:32])

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
	case TraceReasonSRv6Encap, TraceReasonEncryptOverlay:
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
	traceNotifyLength = map[uint16]uint{
		TraceNotifyVersion0: traceNotifyV0Len,
		TraceNotifyVersion1: traceNotifyV1Len,
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
	TraceReasonEncryptOverlay
	// TraceReasonEncryptMask is the bit used to indicate encryption or not.
	TraceReasonEncryptMask = uint8(0x80)
)

/* keep in sync with api/v1/flow/flow.proto */
var traceReasons = map[uint8]string{
	TraceReasonPolicy:               "new",
	TraceReasonCtEstablished:        "established",
	TraceReasonCtReply:              "reply",
	TraceReasonCtRelated:            "related",
	TraceReasonCtDeprecatedReopened: "reopened",
	TraceReasonUnknown:              "unknown",
	TraceReasonSRv6Encap:            "srv6-encap",
	TraceReasonSRv6Decap:            "srv6-decap",
	TraceReasonEncryptOverlay:       "encrypt-overlay",
}

// DecodeTraceNotify will decode 'data' into the provided TraceNotify structure
func DecodeTraceNotify(data []byte, tn *TraceNotify) error {
	return tn.decodeTraceNotify(data)
}

// dumpIdentity dumps the source and destination identities in numeric or
// human-readable format.
func (n *TraceNotify) dumpIdentity(buf *bufio.Writer, numeric DisplayFormat) {
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
	return traceNotifyLength[n.Version]
}

// DumpInfo prints a summary of the trace messages.
func (n *TraceNotify) DumpInfo(data []byte, numeric DisplayFormat, linkMonitor getters.LinkGetter) {
	buf := bufio.NewWriter(os.Stdout)
	hdrLen := n.DataOffset()
	if enc := n.encryptReasonString(); enc != "" {
		fmt.Fprintf(buf, "%s %s flow %#x ",
			n.traceSummary(), enc, n.Hash)
	} else {
		fmt.Fprintf(buf, "%s flow %#x ", n.traceSummary(), n.Hash)
	}
	n.dumpIdentity(buf, numeric)
	ifname := linkMonitor.Name(n.Ifindex)
	fmt.Fprintf(buf, " state %s ifindex %s orig-ip %s: %s\n", n.traceReasonString(),
		ifname, n.OriginalIP().String(), GetConnectionSummary(data[hdrLen:], &decodeOpts{n.IsL3Device(), n.IsIPv6()}))
	buf.Flush()
}

// DumpVerbose prints the trace notification in human readable form
func (n *TraceNotify) DumpVerbose(dissect bool, data []byte, prefix string, numeric DisplayFormat, linkMonitor getters.LinkGetter) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "%s MARK %#x FROM %d %s: %d bytes (%d captured), state %s",
		prefix, n.Hash, n.Source, api.TraceObservationPoint(n.ObsPoint), n.OrigLen, n.CapLen, n.traceReasonString())

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
		Dissect(dissect, data[hdrLen:])
	}
	buf.Flush()
}

func (n *TraceNotify) getJSON(data []byte, cpuPrefix string, linkMonitor getters.LinkGetter) (string, error) {
	v := TraceNotifyToVerbose(n, linkMonitor)
	v.CPUPrefix = cpuPrefix
	hdrLen := n.DataOffset()
	if n.CapLen > 0 && len(data) > int(hdrLen) {
		v.Summary = GetDissectSummary(data[hdrLen:])
	}

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (n *TraceNotify) DumpJSON(data []byte, cpuPrefix string, linkMonitor getters.LinkGetter) {
	resp, err := n.getJSON(data, cpuPrefix, linkMonitor)
	if err == nil {
		fmt.Println(resp)
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

	Source   uint16                   `json:"source"`
	Bytes    uint32                   `json:"bytes"`
	SrcLabel identity.NumericIdentity `json:"srcLabel"`
	DstLabel identity.NumericIdentity `json:"dstLabel"`
	DstID    uint16                   `json:"dstID"`

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
	}
}
