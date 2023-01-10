// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// traceNotifyCommonLen is the minimum length required to determine the version of the TN event.
	traceNotifyCommonLen = 16
	// traceNotifyV0Len is the amount of packet data provided in a trace notification v0.
	traceNotifyV0Len = 32
	// traceNotifyV1Len is the amount of packet data provided in a trace notification v1.
	traceNotifyV1Len = 48
	// TraceReasonEncryptMask is the bit used to indicate encryption or not
	TraceReasonEncryptMask uint8 = 0x80
)

const (
	// TraceNotifyFlagIsIPv6 is set in TraceNotify.Flags when the
	// notification refers to an IPv6 flow
	TraceNotifyFlagIsIPv6 uint8 = 1
)

const (
	TraceNotifyVersion0 = iota
	TraceNotifyVersion1
)

// TraceNotifyV0 is the common message format for versions 0 and 1.
type TraceNotifyV0 struct {
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
	// data
}

// TraceNotifyV1 is the version 1 message format.
type TraceNotifyV1 struct {
	TraceNotifyV0
	OrigIP types.IPv6
	// data
}

// TraceNotify is the message format of a trace notification in the BPF ring buffer
type TraceNotify TraceNotifyV1

var (
	traceNotifyLength = map[uint16]uint{
		TraceNotifyVersion0: traceNotifyV0Len,
		TraceNotifyVersion1: traceNotifyV1Len,
	}
)

// Reasons for forwarding a packet.
const (
	TraceReasonPolicy = iota
	TraceReasonCtEstablished
	TraceReasonCtReply
	TraceReasonCtRelated
	TraceReasonCtReopened
	TraceReasonUnknown
)

var traceReasons = map[uint8]string{
	TraceReasonPolicy:        "new",
	TraceReasonCtEstablished: "established",
	TraceReasonCtReply:       "reply",
	TraceReasonCtRelated:     "related",
	TraceReasonCtReopened:    "reopened",
	TraceReasonUnknown:       "unknown",
}

func connState(reason uint8) string {
	r := reason & ^TraceReasonEncryptMask
	if str, ok := traceReasons[r]; ok {
		return str
	}
	return fmt.Sprintf("%d", reason)
}

func TraceReasonIsKnown(reason uint8) bool {
	switch reason {
	case TraceReasonUnknown:
		return false
	default:
		return true
	}
}

// DecodeTraceNotify will decode 'data' into the provided TraceNotify structure
func DecodeTraceNotify(data []byte, tn *TraceNotify) error {
	if len(data) < traceNotifyCommonLen {
		return fmt.Errorf("Unknown trace event")
	}

	offset := unsafe.Offsetof(tn.Version)
	length := unsafe.Sizeof(tn.Version)
	version := byteorder.Native.Uint16(data[offset : offset+length])

	switch version {
	case TraceNotifyVersion0:
		return binary.Read(bytes.NewReader(data), byteorder.Native, &tn.TraceNotifyV0)
	case TraceNotifyVersion1:
		return binary.Read(bytes.NewReader(data), byteorder.Native, tn)
	}
	return fmt.Errorf("Unrecognized trace event (version %d)", version)
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

func (n *TraceNotify) encryptReason() string {
	if (n.Reason & TraceReasonEncryptMask) != 0 {
		return "encrypted "
	}
	return ""
}

func (n *TraceNotify) traceReason() string {
	return connState(n.Reason)
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
	default:
		return "unknown trace"
	}
}

// OriginalIP returns the original source IP if reverse NAT was performed on
// the flow
func (n *TraceNotify) OriginalIP() net.IP {
	if (n.Flags & TraceNotifyFlagIsIPv6) != 0 {
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
	if n.encryptReason() != "" {
		fmt.Fprintf(buf, "%s %s flow %#x ",
			n.traceSummary(), n.encryptReason(), n.Hash)
	} else {
		fmt.Fprintf(buf, "%s flow %#x ", n.traceSummary(), n.Hash)
	}
	n.dumpIdentity(buf, numeric)
	ifname := linkMonitor.Name(n.Ifindex)
	fmt.Fprintf(buf, " state %s ifindex %s orig-ip %s: %s\n", n.traceReason(),
		ifname, n.OriginalIP().String(), GetConnectionSummary(data[hdrLen:]))
	buf.Flush()
}

// DumpVerbose prints the trace notification in human readable form
func (n *TraceNotify) DumpVerbose(dissect bool, data []byte, prefix string, numeric DisplayFormat, linkMonitor getters.LinkGetter) {
	buf := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(buf, "%s MARK %#x FROM %d %s: %d bytes (%d captured), state %s",
		prefix, n.Hash, n.Source, api.TraceObservationPoint(n.ObsPoint), n.OrigLen, n.CapLen, connState(n.Reason))

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
		State:            connState(n.Reason),
		ObservationPoint: api.TraceObservationPoint(n.ObsPoint),
		TraceSummary:     n.traceSummary(),
		Source:           n.Source,
		Bytes:            n.OrigLen,
		SrcLabel:         n.SrcLabel,
		DstLabel:         n.DstLabel,
		DstID:            n.DstID,
	}
}
