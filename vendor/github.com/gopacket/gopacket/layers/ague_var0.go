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

	"github.com/gopacket/gopacket"
)

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
	hlen := uint8(len(l.Extensions))
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
func (l *AGUEVar0) DecodeFromBytes(data []byte, _ gopacket.DecodeFeedback) error {
	l.Version = data[0] >> 6
	l.C = data[0]&0x20 != 0
	l.Protocol = IPProtocol(data[1])
	l.Flags = (uint16(data[2]) << 8) | uint16(data[3])
	hlen := data[0] & 0x1f
	l.Extensions = data[4 : 4+hlen]
	l.Data = data[4+hlen:]
	return nil
}

// NextLayerType returns the next layer type, e.g. LayerTypeIPv4
func (l AGUEVar0) NextLayerType() gopacket.LayerType {
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
