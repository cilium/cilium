// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"github.com/google/gopacket"
)

// EAPOL defines an EAP over LAN (802.1x) layer.
type EAPOL struct {
	BaseLayer
	Version uint8
	Type    EAPOLType
	Length  uint16
}

// LayerType returns LayerTypeEAPOL.
func (e *EAPOL) LayerType() gopacket.LayerType { return LayerTypeEAPOL }

// DecodeFromBytes decodes the given bytes into this layer.
func (e *EAPOL) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	e.Version = data[0]
	e.Type = EAPOLType(data[1])
	e.Length = binary.BigEndian.Uint16(data[2:4])
	e.BaseLayer = BaseLayer{data[:4], data[4:]}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer
func (e *EAPOL) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, _ := b.PrependBytes(4)
	bytes[0] = e.Version
	bytes[1] = byte(e.Type)
	binary.BigEndian.PutUint16(bytes[2:], e.Length)
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (e *EAPOL) CanDecode() gopacket.LayerClass {
	return LayerTypeEAPOL
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (e *EAPOL) NextLayerType() gopacket.LayerType {
	return e.Type.LayerType()
}

func decodeEAPOL(data []byte, p gopacket.PacketBuilder) error {
	e := &EAPOL{}
	return decodingLayerDecoder(e, data, p)
}
