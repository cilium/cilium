// Copyright 2016 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"

	"github.com/google/gopacket"
)

// Geneve is specifed here https://tools.ietf.org/html/draft-ietf-nvo3-geneve-03
// Geneve Header:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Virtual Network Identifier (VNI)       |    Reserved   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Variable Length Options                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Geneve struct {
	BaseLayer
	Version        uint8        // 2 bits
	OptionsLength  uint8        // 6 bits
	OAMPacket      bool         // 1 bits
	CriticalOption bool         // 1 bits
	Protocol       EthernetType // 16 bits
	VNI            uint32       // 24bits
	Options        []*GeneveOption
}

// Geneve Tunnel Options
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Option Class         |      Type     |R|R|R| Length  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Variable Option Data                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type GeneveOption struct {
	Class  uint16 // 16 bits
	Type   uint8  // 8 bits
	Flags  uint8  // 3 bits
	Length uint8  // 5 bits
	Data   []byte
}

// LayerType returns LayerTypeGeneve
func (gn *Geneve) LayerType() gopacket.LayerType { return LayerTypeGeneve }

func decodeGeneveOption(data []byte, gn *Geneve) (*GeneveOption, uint8) {
	opt := &GeneveOption{}

	opt.Class = binary.BigEndian.Uint16(data[0:1])
	opt.Type = data[2]
	opt.Flags = data[3] >> 4
	opt.Length = data[3] & 0xf

	copy(opt.Data, data[4:opt.Length])

	return opt, 4 + opt.Length
}

func (gn *Geneve) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	gn.Version = data[0] >> 7
	gn.OptionsLength = data[0] & 0x3f

	gn.OAMPacket = data[1]&0x80 > 0
	gn.CriticalOption = data[1]&0x40 > 0
	gn.Protocol = EthernetType(binary.BigEndian.Uint16(data[2:4]))

	var buf [4]byte
	copy(buf[1:], data[4:7])
	gn.VNI = binary.BigEndian.Uint32(buf[:])

	offset, length := uint8(8), gn.OptionsLength
	for length > 0 {
		opt, len := decodeGeneveOption(data[offset:], gn)
		gn.Options = append(gn.Options, opt)

		length -= len
		offset += len
	}

	gn.BaseLayer = BaseLayer{data[:offset], data[offset:]}

	return nil
}

func (gn *Geneve) NextLayerType() gopacket.LayerType {
	return gn.Protocol.LayerType()
}

func decodeGeneve(data []byte, p gopacket.PacketBuilder) error {
	gn := &Geneve{}
	return decodingLayerDecoder(gn, data, p)
}
