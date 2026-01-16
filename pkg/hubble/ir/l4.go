// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// Layer4 tracks L4 protocol specification.
type Layer4 struct {
	IGMP   IGMP `json:"IGMP,omitempty"`
	TCP    TCP  `json:"TCP,omitempty"`
	SCTP   SCTP `json:"SCTP,omitempty"`
	VRRP   VRRP `json:"VRRP,omitempty"`
	UDP    UDP  `json:"UDP,omitempty"`
	ICMPv4 ICMP `json:"ICMPv4,omitempty"`
	ICMPv6 ICMP `json:"ICMPv6,omitempty"`
}

// IsEmpty returns true if target is empty.
func (l4 Layer4) IsEmpty() bool {
	return l4.TCP.IsEmpty() &&
		l4.UDP.IsEmpty() &&
		l4.ICMPv4.IsEmpty() &&
		l4.ICMPv6.IsEmpty() &&
		l4.SCTP.IsEmpty() &&
		l4.VRRP.IsEmpty() &&
		l4.IGMP.IsEmpty()
}

func (l4 Layer4) toProto() *flow.Layer4 {
	if l4.IsEmpty() {
		return nil
	}

	var fl4 flow.Layer4

	if !l4.TCP.IsEmpty() {
		fl4.Protocol = &flow.Layer4_TCP{
			TCP: l4.TCP.toProto(),
		}
	}

	if !l4.UDP.IsEmpty() {
		fl4.Protocol = &flow.Layer4_UDP{
			UDP: l4.UDP.toProto(),
		}
	}

	if !l4.ICMPv4.IsEmpty() {
		fl4.Protocol = &flow.Layer4_ICMPv4{
			ICMPv4: l4.ICMPv4.toProtoV4(),
		}
	}

	if !l4.ICMPv6.IsEmpty() {
		fl4.Protocol = &flow.Layer4_ICMPv6{
			ICMPv6: l4.ICMPv6.toProtoV6(),
		}
	}

	if !l4.SCTP.IsEmpty() {
		fl4.Protocol = &flow.Layer4_SCTP{
			SCTP: l4.SCTP.toProto(),
		}
	}

	if !l4.VRRP.IsEmpty() {
		fl4.Protocol = &flow.Layer4_VRRP{
			VRRP: l4.VRRP.toProto(),
		}
	}

	if !l4.IGMP.IsEmpty() {
		fl4.Protocol = &flow.Layer4_IGMP{
			IGMP: l4.IGMP.toProto(),
		}
	}

	return &fl4
}

func protoToL4(l4 *flow.Layer4) Layer4 {
	var l Layer4

	if l4.GetTCP() != nil {
		l.TCP = protoToTCP(l4.GetTCP())
	}
	if l4.GetUDP() != nil {
		l.UDP = protoToUDP(l4.GetUDP())
	}
	if l4.GetICMPv4() != nil {
		l.ICMPv4 = protoToICMPv4(l4.GetICMPv4())
	}
	if l4.GetICMPv6() != nil {
		l.ICMPv6 = protoToICMPv6(l4.GetICMPv6())
	}
	if l4.GetSCTP() != nil {
		l.SCTP = protoToSCTP(l4.GetSCTP())
	}
	if l4.GetVRRP() != nil {
		l.VRRP = protoToVRRP(l4.GetVRRP())
	}
	if l4.GetIGMP() != nil {
		l.IGMP = protoToIGMP(l4.GetIGMP())
	}

	return l
}

// IGMP tracks IGMP layer information.
type IGMP struct {
	GroupAddress string `json:"groupAddress,omitempty"`
	Type         uint32 `json:"type,omitempty"`
}

// IsEmpty returns true if target is empty.
func (i IGMP) IsEmpty() bool {
	return i.Type == 0 && i.GroupAddress == ""
}

func (i IGMP) toProto() *flow.IGMP {
	if i.IsEmpty() {
		return nil
	}

	return &flow.IGMP{
		Type:         i.Type,
		GroupAddress: i.GroupAddress,
	}
}

func protoToIGMP(i *flow.IGMP) IGMP {
	if i == nil {
		return IGMP{}
	}

	return IGMP{
		Type:         i.Type,
		GroupAddress: i.GroupAddress,
	}
}

// VRRP tracks VRRP layer information.
type VRRP struct {
	Type     uint32 `json:"type,omitempty"`
	VRID     uint32 `json:"vrid,omitempty"`
	Priority uint32 `json:"priority,omitempty"`
}

// IsEmpty returns true if target is empty.
func (v VRRP) IsEmpty() bool {
	return v.Type == 0 && v.VRID == 0 && v.Priority == 0
}

func (v VRRP) toProto() *flow.VRRP {
	if v.IsEmpty() {
		return nil
	}

	return &flow.VRRP{
		Type:     v.Type,
		Vrid:     v.VRID,
		Priority: v.Priority,
	}
}

func protoToVRRP(i *flow.VRRP) VRRP {
	if i == nil {
		return VRRP{}
	}

	return VRRP{
		Type:     i.Type,
		VRID:     i.Vrid,
		Priority: i.Priority,
	}
}

// SCTP tracks SCTP layer information.
type SCTP struct {
	SourcePort      uint32             `json:"sourcePort,omitempty"`
	DestinationPort uint32             `json:"destinationPort,omitempty"`
	ChunkType       flow.SCTPChunkType `json:"chunkType,omitempty"`
}

// IsEmpty returns true if target is empty.
func (s SCTP) IsEmpty() bool {
	return s.SourcePort == 0 && s.DestinationPort == 0 && s.ChunkType == flow.SCTPChunkType_UNSUPPORTED
}

func (s SCTP) toProto() *flow.SCTP {
	if s.IsEmpty() {
		return nil
	}

	return &flow.SCTP{
		SourcePort:      s.SourcePort,
		DestinationPort: s.DestinationPort,
		ChunkType:       s.ChunkType,
	}
}

func protoToSCTP(i *flow.SCTP) SCTP {
	if i == nil {
		return SCTP{}
	}

	return SCTP{
		SourcePort:      i.SourcePort,
		DestinationPort: i.DestinationPort,
		ChunkType:       i.ChunkType,
	}
}

// ICMP tracks ICMP layer information.
type ICMP struct {
	Type uint32 `json:"type,omitempty"`
	Code uint32 `json:"code,omitempty"`
}

// IsEmpty returns true if target is empty.
func (i ICMP) IsEmpty() bool {
	return i.Type == 0 && i.Code == 0
}

func (i ICMP) toProtoV6() *flow.ICMPv6 {
	if i.IsEmpty() {
		return nil
	}

	return &flow.ICMPv6{
		Type: i.Type,
		Code: i.Code,
	}
}

func (i ICMP) toProtoV4() *flow.ICMPv4 {
	if i.IsEmpty() {
		return nil
	}

	return &flow.ICMPv4{
		Type: i.Type,
		Code: i.Code,
	}
}

func protoToICMPv4(i *flow.ICMPv4) ICMP {
	if i == nil {
		return ICMP{}
	}

	return ICMP{
		Type: i.Type,
		Code: i.Code,
	}
}

func protoToICMPv6(i *flow.ICMPv6) ICMP {
	if i == nil {
		return ICMP{}
	}

	return ICMP{
		Type: i.Type,
		Code: i.Code,
	}
}

// UDP tracks UDP layer information.
type UDP struct {
	SourcePort      uint32 `json:"sourcePort,omitempty"`
	DestinationPort uint32 `json:"destinationPort,omitempty"`
}

// IsEmpty returns true if target is empty.
func (u UDP) IsEmpty() bool {
	return u.SourcePort == 0 && u.DestinationPort == 0
}

func (u UDP) toProto() *flow.UDP {
	if u.IsEmpty() {
		return nil
	}

	return &flow.UDP{
		SourcePort:      u.SourcePort,
		DestinationPort: u.DestinationPort,
	}
}

func protoToUDP(u *flow.UDP) UDP {
	if u == nil {
		return UDP{}
	}

	return UDP{
		SourcePort:      u.SourcePort,
		DestinationPort: u.DestinationPort,
	}
}

// TCP tracks TCP layer information.
type TCP struct {
	Flags           TCPFlags `json:"flags,omitempty"`
	SourcePort      uint32   `json:"sourcePort,omitempty"`
	DestinationPort uint32   `json:"destinationPort,omitempty"`
}

// IsEmpty returns true if target is empty.
func (t TCP) IsEmpty() bool {
	return t.SourcePort == 0 && t.DestinationPort == 0 && t.Flags == TCPFlags{}
}

func (t TCP) toProto() *flow.TCP {
	if t.IsEmpty() {
		return nil
	}

	return &flow.TCP{
		SourcePort:      t.SourcePort,
		DestinationPort: t.DestinationPort,
		Flags:           t.Flags.toProto(),
	}
}

func protoToTCP(t *flow.TCP) TCP {
	if t == nil {
		return TCP{}
	}

	return TCP{
		SourcePort:      t.SourcePort,
		DestinationPort: t.DestinationPort,
		Flags:           protoToTCPFlags(t),
	}
}

// TCPFlags tracks TCP flags.
type TCPFlags struct {
	FIN bool `json:"fin,omitempty"`
	SYN bool `json:"syn,omitempty"`
	RST bool `json:"rst,omitempty"`
	PSH bool `json:"psh,omitempty"`
	ACK bool `json:"ack,omitempty"`
	URG bool `json:"urg,omitempty"`
	ECE bool `json:"ece,omitempty"`
	CWR bool `json:"cwr,omitempty"`
	NS  bool `json:"ns,omitempty"`
}

// IsEmpty returns true if no flags are set.
func (f TCPFlags) IsEmpty() bool {
	return !f.FIN && !f.SYN && !f.RST && !f.PSH && !f.ACK && !f.URG && !f.ECE && !f.CWR && !f.NS
}

func (f TCPFlags) toProto() *flow.TCPFlags {
	if f.IsEmpty() {
		return nil
	}

	return &flow.TCPFlags{
		FIN: f.FIN,
		SYN: f.SYN,
		RST: f.RST,
		PSH: f.PSH,
		ACK: f.ACK,
		URG: f.URG,
		ECE: f.ECE,
		CWR: f.CWR,
		NS:  f.NS,
	}
}

func protoToTCPFlags(t *flow.TCP) TCPFlags {
	if t == nil || t.Flags == nil {
		return TCPFlags{}
	}
	return TCPFlags{
		FIN: t.Flags.FIN,
		SYN: t.Flags.SYN,
		RST: t.Flags.RST,
		PSH: t.Flags.PSH,
		ACK: t.Flags.ACK,
		URG: t.Flags.URG,
		ECE: t.Flags.ECE,
		CWR: t.Flags.CWR,
		NS:  t.Flags.NS,
	}
}
