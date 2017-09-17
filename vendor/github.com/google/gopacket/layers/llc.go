// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

// LLC is the layer used for 802.2 Logical Link Control headers.
// See http://standards.ieee.org/getieee802/download/802.2-1998.pdf
type LLC struct {
	BaseLayer
	DSAP    uint8
	IG      bool // true means group, false means individual
	SSAP    uint8
	CR      bool // true means response, false means command
	Control uint16
}

// LayerType returns gopacket.LayerTypeLLC.
func (l *LLC) LayerType() gopacket.LayerType { return LayerTypeLLC }

// SNAP is used inside LLC.  See
// http://standards.ieee.org/getieee802/download/802-2001.pdf.
// From http://en.wikipedia.org/wiki/Subnetwork_Access_Protocol:
//  "[T]he Subnetwork Access Protocol (SNAP) is a mechanism for multiplexing,
//  on networks using IEEE 802.2 LLC, more protocols than can be distinguished
//  by the 8-bit 802.2 Service Access Point (SAP) fields."
type SNAP struct {
	BaseLayer
	OrganizationalCode []byte
	Type               EthernetType
}

// LayerType returns gopacket.LayerTypeSNAP.
func (s *SNAP) LayerType() gopacket.LayerType { return LayerTypeSNAP }

func decodeLLC(data []byte, p gopacket.PacketBuilder) error {
	l := &LLC{
		DSAP:    data[0] & 0xFE,
		IG:      data[0]&0x1 != 0,
		SSAP:    data[1] & 0xFE,
		CR:      data[1]&0x1 != 0,
		Control: uint16(data[2]),
	}
	if l.Control&0x1 == 0 || l.Control&0x3 == 0x1 {
		l.Control = l.Control<<8 | uint16(data[3])
		l.Contents = data[:4]
		l.Payload = data[4:]
	} else {
		l.Contents = data[:3]
		l.Payload = data[3:]
	}
	p.AddLayer(l)
	if l.DSAP == 0xAA && l.SSAP == 0xAA {
		return p.NextDecoder(LayerTypeSNAP)
	}
	return p.NextDecoder(gopacket.DecodeUnknown)
}

func decodeSNAP(data []byte, p gopacket.PacketBuilder) error {
	s := &SNAP{
		OrganizationalCode: data[:3],
		Type:               EthernetType(binary.BigEndian.Uint16(data[3:5])),
		BaseLayer:          BaseLayer{data[:5], data[5:]},
	}
	p.AddLayer(s)
	// BUG(gconnell):  When decoding SNAP, we treat the SNAP type as an Ethernet
	// type.  This may not actually be an ethernet type in all cases,
	// depending on the organizational code.  Right now, we don't check.
	return p.NextDecoder(s.Type)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l *LLC) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var ig_flag, cr_flag byte
	var length int

	if l.Control&0xFF00 != 0 {
		length = 4
	} else {
		length = 3
	}

	if l.DSAP&0x1 != 0 {
		return errors.New("DSAP value invalid, should not include IG flag bit")
	}

	if l.SSAP&0x1 != 0 {
		return errors.New("SSAP value invalid, should not include CR flag bit")
	}

	if buf, err := b.PrependBytes(length); err != nil {
		return err
	} else {
		ig_flag = 0
		if l.IG {
			ig_flag = 0x1
		}

		cr_flag = 0
		if l.CR {
			cr_flag = 0x1
		}

		buf[0] = l.DSAP + ig_flag
		buf[1] = l.SSAP + cr_flag

		if length == 4 {
			buf[2] = uint8(l.Control >> 8)
			buf[3] = uint8(l.Control)
		} else {
			buf[2] = uint8(l.Control)
		}
	}

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (s *SNAP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if buf, err := b.PrependBytes(5); err != nil {
		return err
	} else {
		buf[0] = s.OrganizationalCode[0]
		buf[1] = s.OrganizationalCode[1]
		buf[2] = s.OrganizationalCode[2]
		binary.BigEndian.PutUint16(buf[3:5], uint16(s.Type))
	}

	return nil
}
