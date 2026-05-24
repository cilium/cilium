// Copyright 2024 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
)

const LinkTypeApplePKTAP LinkType = 149 // Apple pktap wrapper (Darwin only)

// pktap v1 record types
const (
	PKTRecNone   = 0
	PKTRecPacket = 1
)

// pktap v1 direction flags (lower 2 bits of pkt_flags)
const (
	PTHFlagDirIn  = 0x00000001
	PTHFlagDirOut = 0x00000002
)

// PktapDirection represents the direction of a packet
type PktapDirection uint32

func (d PktapDirection) String() string {
	switch d {
	case PTHFlagDirIn:
		return "in"
	case PTHFlagDirOut:
		return "out"
	}
	return ""
}

// ServiceClass represents the SO_TC_* service class values
type ServiceClass uint32

func (s ServiceClass) String() string {
	switch s {
	case 0:
		return "BK_SYS"
	case 1:
		return "BK"
	case 2:
		return "BE"
	case 3:
		return "RD"
	case 4:
		return "OAM"
	case 5:
		return "AV"
	case 6:
		return "RV"
	case 7:
		return "VI"
	case 8:
		return "VO"
	case 9:
		return "CTL"
	}
	return fmt.Sprintf("UNK(%d)", s)
}

// PktapV1 is the Darwin-specific pktap v1 metadata header.
// It wraps packets with process/connection metadata at the kernel level.
// see: https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.81.4/bsd/net/pktap.h#L89-L114
type PktapV1 struct {
	BaseLayer
	HeaderLength           uint32       // 0x00: total header length (156)
	RecordType             uint32       // 0x04: PKT_REC_PACKET=1
	DLT                    uint32       // 0x08: DLT type of inner packet
	InterfaceName          string       // 0x0C: interface name (24 bytes)
	Flags                  uint32       // 0x24: direction and other flags
	ProtocolFamily         uint32       // 0x28: protocol family (AF_INET=2, AF_INET6=30)
	LinkLayerHeaderLength  uint32       // 0x2C: link-layer header length
	LinkLayerTrailerLength uint32       // 0x30: link-layer trailer length
	PID                    uint32       // 0x34: process ID
	CommandName            string       // 0x38: command name (20 bytes)
	ServiceClass           ServiceClass // 0x4C: service class
	InterfaceType          uint16       // 0x50: interface type
	InterfaceUnit          uint16       // 0x52: unit number
	EffectivePID           uint32       // 0x54: effective process ID
	EffectiveCommandName   string       // 0x58: effective command name (20 bytes)
}

// LayerType returns LayerTypePktap.
func (p *PktapV1) LayerType() gopacket.LayerType { return LayerTypePktap }

// Direction returns the packet direction (in/out)
func (p *PktapV1) Direction() PktapDirection {
	return PktapDirection(p.Flags & 0x3)
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (p *PktapV1) CanDecode() gopacket.LayerClass {
	return LayerTypePktap
}

// NextLayerType returns the layer type of the inner packet (determined by DLT)
func (p *PktapV1) NextLayerType() gopacket.LayerType {
	return LinkType(p.DLT).LayerType()
}

// DecodeFromBytes decodes the given bytes into this layer.
func (p *PktapV1) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	//sizeof(struct pktap_header) == 156
	if len(data) < 156 {
		return errors.New("pktap packet too small")
	}

	p.HeaderLength = binary.LittleEndian.Uint32(data[0:4])
	if p.HeaderLength < 156 {
		return fmt.Errorf("pktap v1 header length mismatch: got %d", p.HeaderLength)
	}

	p.RecordType = binary.LittleEndian.Uint32(data[4:8])
	if p.RecordType != PKTRecPacket {
		return fmt.Errorf("pktap unsupported record type: %d", p.RecordType)
	}

	p.DLT = binary.LittleEndian.Uint32(data[8:12])

	// Interface name: 24 bytes at offset 0x0C, null-terminated
	ifname := string(data[0x0C : 0x0C+24])
	if nullIdx := strings.Index(ifname, "\x00"); nullIdx >= 0 {
		ifname = ifname[:nullIdx]
	}
	p.InterfaceName = ifname

	p.Flags = binary.LittleEndian.Uint32(data[0x24:0x28])
	p.ProtocolFamily = binary.LittleEndian.Uint32(data[0x28:0x2C])
	p.LinkLayerHeaderLength = binary.LittleEndian.Uint32(data[0x2C:0x30])
	p.LinkLayerTrailerLength = binary.LittleEndian.Uint32(data[0x30:0x34])
	p.PID = binary.LittleEndian.Uint32(data[0x34:0x38])

	// Command name: 20 bytes at offset 0x38, null-terminated
	cmdname := string(data[0x38 : 0x38+20])
	if nullIdx := strings.Index(cmdname, "\x00"); nullIdx >= 0 {
		cmdname = cmdname[:nullIdx]
	}
	p.CommandName = cmdname

	p.ServiceClass = ServiceClass(binary.LittleEndian.Uint32(data[0x4C:0x50]))
	p.InterfaceType = binary.LittleEndian.Uint16(data[0x50:0x52])
	p.InterfaceUnit = binary.LittleEndian.Uint16(data[0x52:0x54])
	p.EffectivePID = binary.LittleEndian.Uint32(data[0x54:0x58])

	// Effective command name: 20 bytes at offset 0x58, null-terminated
	ecmdname := string(data[0x58 : 0x58+20])
	if nullIdx := strings.Index(ecmdname, "\x00"); nullIdx >= 0 {
		ecmdname = ecmdname[:nullIdx]
	}
	p.EffectiveCommandName = ecmdname

	p.BaseLayer = BaseLayer{Contents: data[:p.HeaderLength], Payload: data[p.HeaderLength:]}
	return nil
}

// String returns a human-readable representation of the pktap metadata.
func (p *PktapV1) String() string {
	return fmt.Sprintf("PktapV1(%s, proc %s:%d, eproc %s:%d, svc %s, %s, DLT %s (%d))",
		p.InterfaceName,
		p.CommandName, p.PID,
		p.EffectiveCommandName, p.EffectivePID,
		p.ServiceClass,
		p.Direction(),
		LinkType(p.DLT), p.DLT)
}

func decodePktapV1(data []byte, p gopacket.PacketBuilder) error {
	pktap := &PktapV1{}
	if err := pktap.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(pktap)
	return p.NextDecoder(LinkType(pktap.DLT))
}
