// Copyright 2016 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// Geneve is specifed here https://tools.ietf.org/html/draft-ietf-nvo3-geneve-03
// Geneve Header:
//
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        Virtual Network Identifier (VNI)       |    Reserved   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Variable Length Options                    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
//
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          Option Class         |      Type     |R|R|R| Length  |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                      Variable Option Data                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type GeneveOption struct {
	Class  uint16 // 16 bits
	Type   uint8  // 8 bits
	Flags  uint8  // 3 bits
	Length uint8  // 5 bits
	Data   []byte
}

// ensure Geneve implements DecodingLayer.
var _ gopacket.DecodingLayer = (*Geneve)(nil)

// LayerType returns LayerTypeGeneve
func (gn *Geneve) LayerType() gopacket.LayerType { return LayerTypeGeneve }

func decodeGeneveOption(data []byte, gn *Geneve, df gopacket.DecodeFeedback) (*GeneveOption, uint8, error) {
	if len(data) < 3 {
		df.SetTruncated()
		return nil, 0, errors.New("geneve option too small")
	}
	opt := &GeneveOption{}

	opt.Class = binary.BigEndian.Uint16(data[0:2])
	opt.Type = data[2]
	opt.Flags = data[3] >> 5
	opt.Length = (data[3]&0x1f)*4 + 4

	if len(data) < int(opt.Length) {
		df.SetTruncated()
		return nil, 0, errors.New("geneve option too small")
	}
	opt.Data = make([]byte, opt.Length-4)
	copy(opt.Data, data[4:opt.Length])

	return opt, opt.Length, nil
}

func (gn *Geneve) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 7 {
		df.SetTruncated()
		return errors.New("geneve packet too short")
	}

	gn.Version = data[0] >> 7
	gn.OptionsLength = (data[0] & 0x3f) * 4
	gn.Options = gn.Options[:0]

	gn.OAMPacket = data[1]&0x80 > 0
	gn.CriticalOption = data[1]&0x40 > 0
	gn.Protocol = EthernetType(binary.BigEndian.Uint16(data[2:4]))

	var buf [4]byte
	copy(buf[1:], data[4:7])
	gn.VNI = binary.BigEndian.Uint32(buf[:])

	offset, length := uint8(8), int32(gn.OptionsLength)
	if len(data) < int(length+7) {
		df.SetTruncated()
		return errors.New("geneve packet too short")
	}

	for length > 0 {
		opt, len, err := decodeGeneveOption(data[offset:], gn, df)
		if err != nil {
			return err
		}
		gn.Options = append(gn.Options, opt)

		length -= int32(len)
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

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (gn *Geneve) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var optionsLength int
	for _, o := range gn.Options {
		dataLen := len(o.Data) & ^3
		optionsLength += 4 + dataLen
	}
	if opts.FixLengths {
		gn.OptionsLength = uint8(optionsLength)
	}

	plen := int(8 + optionsLength)
	bytes, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}

	// PrependBytes does not guarantee that bytes are zeroed.  Setting flags via OR requires that they start off at zero
	bytes[0] = 0
	bytes[1] = 0

	// Construct Geneve

	bytes[0] |= gn.Version << 6
	bytes[0] |= ((gn.OptionsLength >> 2) & 0x3f)

	if gn.OAMPacket {
		bytes[1] |= 0x80
	}

	if gn.CriticalOption {
		bytes[1] |= 0x40
	}

	binary.BigEndian.PutUint16(bytes[2:4], uint16(gn.Protocol))

	if gn.VNI >= 1<<24 {
		return fmt.Errorf("Virtual Network Identifier = %x exceeds max for 24-bit uint", gn.VNI)
	}
	binary.BigEndian.PutUint32(bytes[4:8], gn.VNI<<8)

	// Construct Options

	offset := 8
	for _, o := range gn.Options {
		dataLen := len(o.Data) & ^3
		if opts.FixLengths {
			o.Length = uint8(4 + dataLen)
		}

		binary.BigEndian.PutUint16(bytes[offset:(offset+2)], uint16(o.Class))

		offset += 2
		bytes[offset] = o.Type

		offset += 1
		bytes[offset] = o.Flags << 5
		bytes[offset] |= ((o.Length - 4) >> 2) & 0x1f

		offset += 1
		copy(bytes[offset:(offset+dataLen)], o.Data)

		offset += dataLen
	}

	return nil
}

// CanDecode implements DecodingLayer.
func (gn *Geneve) CanDecode() gopacket.LayerClass {
	return LayerTypeGeneve
}
