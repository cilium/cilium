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

// An AGUEVar1 header is mostly imaginary, having a length of 0 in its serialized form.
// IPProtocol value is either IPProtocolIPv4 or IPProtocolIPv6, depending on the encapped
// IP header contained in Data, which must begin with the high-order bits 01.
type AGUEVar1 struct {
	Protocol IPProtocol
	Data     []byte
}

// LayerType returns this pseudo-header's type as defined in layertypes.go
func (l AGUEVar1) LayerType() gopacket.LayerType {
	return LayerTypeAGUEVar1
}

// LayerContents returns an empty byte array, because this header has no length.
func (l AGUEVar1) LayerContents() []byte {
	b := make([]byte, 0)
	return b
}

// LayerPayload returns an IPv4 or IPv6 packet in serialized form.
func (l AGUEVar1) LayerPayload() []byte {
	return l.Data
}

// SerializeTo writes our imaginary header into SerializeBuffer. This amount to a noop.
func (l AGUEVar1) SerializeTo(_ gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	return nil
}

// CanDecode returns the type of layer we can decode.
func (l AGUEVar1) CanDecode() gopacket.LayerClass {
	return LayerTypeAGUEVar1
}

// DecodeFromBytes extracts our pseudo-header data from a serialized packet.
// There's only one thing, the next header type, which is either IPv4 or IPv6.
// They are crafted to keep their own header type in the first nibble.
// So we peek into the IP header to get the next-layer protocol type.
func (l *AGUEVar1) DecodeFromBytes(data []byte, _ gopacket.DecodeFeedback) error {
	if len(data) < 1 {
		return errors.New("DecodeFromBytes() failed, no data")
	}
	ipVersion := data[0] >> 4
	if ipVersion == 4 {
		l.Protocol = IPProtocolIPv4
	} else if ipVersion == 6 {
		l.Protocol = IPProtocolIPv6
	} else {
		return errors.New("DecodeFromBytes() failed, unknown IP version")
	}
	l.Data = data
	return nil
}

// NextLayerType returns the next layer type, e.g. LayerTypeIPv4
func (l AGUEVar1) NextLayerType() gopacket.LayerType {
	return l.Protocol.LayerType()
}

// decodeAGUEVar1 decodes packet data to figure out the next-layer IP type,
// then adds AGUEVar1 layer info to the packet object, recursively decodes
// remaining layers, and returns the next-layer type.
func decodeAGUEVar1(data []byte, p gopacket.PacketBuilder) error {
	l := AGUEVar1{}
	if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	p.AddLayer(l)
	return p.NextDecoder(l.NextLayerType())
}
