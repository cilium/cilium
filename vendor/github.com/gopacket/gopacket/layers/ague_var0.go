// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.
package layers

import (
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// agueVar0HlenMask selects the 5-bit Hlen field of the first header byte.
const agueVar0HlenMask = 0x1f

// AGUEVar0 represents a packet encoded with Generic UDP Encapsulation.
// It should sit "under" a UDP layer with dest port 666.
//
// For more information about the meaning of the fields, see
// https://tools.ietf.org/html/draft-ietf-intarea-gue-04#section-3.1
type AGUEVar0 struct {
	Version    uint8
	C          bool
	Protocol   IPProtocol
	Flags      uint16
	Extensions []byte
	Data       []byte
}

// LayerType returns this pseudo-header's type as defined in layertypes.go
func (l AGUEVar0) LayerType() gopacket.LayerType {
	return LayerTypeAGUEVar0
}

// LayerContents returns a byte array containing our serialized header.
func (l AGUEVar0) LayerContents() []byte {
	b := make([]byte, 4, 4+len(l.Extensions))
	// Hlen is a 5-bit count of 32-bit words.
	hlen := uint8(len(l.Extensions)/4) & agueVar0HlenMask
	b[0] = l.Version<<6 | hlen
	if l.C {
		b[0] |= 0x20
	}
	b[0] |= hlen
	b[1] = byte(l.Protocol)
	b[2] = byte(l.Flags >> 8)
	b[3] = byte(l.Flags & 0xff)
	b = append(b, l.Extensions...)
	return b
}

// LayerPayload returns an IPv4 or IPv6 packet in serialized form.
func (l AGUEVar0) LayerPayload() []byte {
	return l.Data
}

// SerializeTo writes our header into SerializeBuffer.
func (l AGUEVar0) SerializeTo(buf gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Refuse extensions the 5-bit word count cannot describe; a receiver
	// would otherwise skip the wrong number of bytes.
	if len(l.Extensions)%4 != 0 || len(l.Extensions)/4 > agueVar0HlenMask {
		return errors.New("AGUE var0 extensions length must be a multiple of 4 and at most 124 bytes")
	}
	b := l.LayerContents()
	writeTo, err := buf.PrependBytes(len(b))
	if err != nil {
		return err
	}
	copy(writeTo, b)
	return nil
}

// CanDecode returns the type of layer we can decode.
func (l AGUEVar0) CanDecode() gopacket.LayerClass {
	return LayerTypeAGUEVar0
}

// DecodeFromBytes extracts our header data from a serialized packet.
func (l *AGUEVar0) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return errors.New("AGUE var0 packet too small")
	}
	l.Version = data[0] >> 6
	if l.Version != 0 {
		// Variant 1 carries no GUE header at all (see AGUEVar1), so the bytes
		// here are an IP header, not ours; variants 2 and 3 are undefined.
		return fmt.Errorf("AGUE var0 packet has variant %d", l.Version)
	}
	l.C = data[0]&0x20 != 0
	l.Protocol = IPProtocol(data[1])
	l.Flags = (uint16(data[2]) << 8) | uint16(data[3])
	// hlen counts 32-bit extension words; compute the bound in int so it cannot
	// wrap past len(data).
	hlen := 4 * int(data[0]&agueVar0HlenMask)
	if 4+hlen > len(data) {
		df.SetTruncated()
		return errors.New("AGUE var0 extensions exceed packet length")
	}
	l.Extensions = data[4 : 4+hlen]
	l.Data = data[4+hlen:]
	return nil
}

// NextLayerType returns the next layer type, e.g. LayerTypeIPv4
func (l AGUEVar0) NextLayerType() gopacket.LayerType {
	// Control message: Protocol holds a control type, not an IP protocol
	// number, and the body is consumed by the decapsulator, not forwarded.
	if l.C {
		return gopacket.LayerTypePayload
	}
	return l.Protocol.LayerType()
}

// decodeAGUE decodes AGUEVar0 or AGUEVar1, depending on the first data byte.
// If AGUEVar1, it refers the packet to AGUEVar1 for decoding.
// Else it adds AGUEVar0 layer info to the packet object, recursively decodes
// remaining layers, and returns the next-layer type (IPv4 or IPv6).
func decodeAGUE(data []byte, p gopacket.PacketBuilder) error {
	if len(data) == 0 {
		return errors.New("decodeAGUE() failed, no data")
	}
	if data[0]>>6 == 1 {
		return decodeAGUEVar1(data, p)
	}
	l := AGUEVar0{}
	if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	p.AddLayer(l)
	return p.NextDecoder(l.NextLayerType())
}
