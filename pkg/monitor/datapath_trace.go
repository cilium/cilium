// Copyright 2016-2019 Authors of Cilium
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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/monitor/api"
)

const (
	// traceNotifyCommonLen is the minimum length required to determine the version of the TN event.
	traceNotifyCommonLen = 16
	// traceNotifyV1Len is the amount of packet data provided in a trace notification v1
	traceNotifyV1Len = 32
	// traceNotifyV2Len is the amount of packet data provided in a trace notification v2
	traceNotifyV2Len = 48
	// TraceReasonEncryptMask is the bit used to indicate encryption or not
	TraceReasonEncryptMask uint8 = 0x80
)

const (
	// TraceNotifyFlagIsIPv6 is set in TraceNotify.Flags when the
	// notification refers to an IPv6 flow
	TraceNotifyFlagIsIPv6 uint8 = 1
)

// TraceNotifyV1 is the message format that is common between the v1 trace
// notifications emitted on Cilium 1.6.x or earlier and the v2 trace on Cilium
// 1.7.x or later.
type TraceNotifyV1 struct {
	Type     uint8
	ObsPoint uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint16
	MetaLen  uint16 // V1 -> traceNotifyV1Len; V2+ -> traceNotifyV2Len
	SrcLabel uint32
	DstLabel uint32
	DstID    uint16
	Reason   uint8
	Flags    uint8
	Ifindex  uint32
	OrigIP   types.IPv6
	// data
}

// TraceNotify is the message format of a trace notification in the BPF ring buffer
type TraceNotify struct {
	TraceNotifyV1
	OrigIP types.IPv6
	// data
}

// Reasons for forwarding a packet.
const (
	TraceReasonPolicy = iota
	TraceReasonCtEstablished
	TraceReasonCtReply
	TraceReasonCtRelated
)

var traceReasons = map[uint8]string{
	TraceReasonPolicy:        "new",
	TraceReasonCtEstablished: "established",
	TraceReasonCtReply:       "reply",
	TraceReasonCtRelated:     "related",
}

func connState(reason uint8) string {
	r := reason & ^TraceReasonEncryptMask
	if str, ok := traceReasons[r]; ok {
		return str
	}
	return fmt.Sprintf("%d", reason)
}

// DecodeTraceNotify will decode 'data' into the provided TraceNotify structure
func DecodeTraceNotify(data []byte, tn *TraceNotify) error {
	if len(data) < traceNotifyCommonLen {
		return fmt.Errorf("Unknown trace event")
	}

	var msgHdrLen uint16
	// metaLenOffset := unsafe.Offsetof(TraceNotify.MetaLen)
	metaLenOffset := 14
	// metaLenSize := unsafe.Sizeof(TraceNotify.MetaLen)
	metaLenSize := 2
	metaLen := data[metaLenOffset : metaLenOffset+metaLenSize]
	err := binary.Read(bytes.NewReader(metaLen), byteorder.Native, &msgHdrLen)
	if err != nil {
		return err
	}

	switch msgHdrLen {
	// Cilium v1.6 or earlier always reports 0 for the length.
	case 0, traceNotifyV1Len:
		err = binary.Read(bytes.NewReader(data), byteorder.Native, &tn.TraceNotifyV1)
		tn.MetaLen = traceNotifyV1Len
	case traceNotifyV2Len:
		err = binary.Read(bytes.NewReader(data), byteorder.Native, tn)
	default:
		err = fmt.Errorf("Unrecognized trace event (len %d)", msgHdrLen)
	}
	return err
}

func (n *TraceNotify) encryptReason() string {
	if (n.Reason & TraceReasonEncryptMask) != 0 {
		return fmt.Sprintf(" encrypted ")
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
		return "-> proxy"
	case api.TraceToHost:
		return "-> host from"
	case api.TraceToStack:
		return "-> stack"
	case api.TraceToOverlay:
		return "-> overlay"
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

// DumpInfo prints a summary of the trace messages.
func (n *TraceNotify) DumpInfo(data []byte) {
	if n.encryptReason() != "" {
		fmt.Printf("%s %s flow %#x identity %d->%d state %s ifindex %s orig-ip %s: %s\n",
			n.traceSummary(), n.encryptReason(), n.Hash, n.SrcLabel, n.DstLabel,
			n.traceReason(), ifname(int(n.Ifindex)), n.OriginalIP().String(), GetConnectionSummary(data[n.MetaLen:]))
	} else {
		fmt.Printf("%s flow %#x identity %d->%d state %s ifindex %s orig-ip %s: %s\n",
			n.traceSummary(), n.Hash, n.SrcLabel, n.DstLabel,
			n.traceReason(), ifname(int(n.Ifindex)), n.OriginalIP().String(), GetConnectionSummary(data[n.MetaLen:]))
	}
}

// DumpVerbose prints the trace notification in human readable form
func (n *TraceNotify) DumpVerbose(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d %s: %d bytes (%d captured), state %s",
		prefix, n.Hash, n.Source, api.TraceObservationPoint(n.ObsPoint), n.OrigLen, n.CapLen, connState(n.Reason))

	if n.Ifindex != 0 {
		fmt.Printf(", interface %s", ifname(int(n.Ifindex)))
	}

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		fmt.Printf(", identity %d->%d", n.SrcLabel, n.DstLabel)
	}

	fmt.Printf(", orig-ip " + n.OriginalIP().String())

	if n.DstID != 0 {
		fmt.Printf(", to endpoint %d\n", n.DstID)
	} else {
		fmt.Printf("\n")
	}

	if n.CapLen > 0 && len(data) > int(n.MetaLen) {
		Dissect(dissect, data[n.MetaLen:])
	}
}

func (n *TraceNotify) getJSON(data []byte, cpuPrefix string) (string, error) {
	v := TraceNotifyToVerbose(n)
	v.CPUPrefix = cpuPrefix
	if n.CapLen > 0 && len(data) > int(n.MetaLen) {
		v.Summary = GetDissectSummary(data[n.MetaLen:])
	}

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (n *TraceNotify) DumpJSON(data []byte, cpuPrefix string) {
	resp, err := n.getJSON(data, cpuPrefix)
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

	Source   uint16 `json:"source"`
	Bytes    uint32 `json:"bytes"`
	SrcLabel uint32 `json:"srcLabel"`
	DstLabel uint32 `json:"dstLabel"`
	DstID    uint16 `json:"dstID"`

	Summary *DissectSummary `json:"summary,omitempty"`
}

// TraceNotifyToVerbose creates verbose notification from base TraceNotify
func TraceNotifyToVerbose(n *TraceNotify) TraceNotifyVerbose {
	return TraceNotifyVerbose{
		Type:             "trace",
		Mark:             fmt.Sprintf("%#x", n.Hash),
		Ifindex:          ifname(int(n.Ifindex)),
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
