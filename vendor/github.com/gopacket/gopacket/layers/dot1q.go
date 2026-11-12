// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/gopacket/gopacket"
)

// ethernetTypeMinValue is the first value of the type/length field that is
// an EtherType; anything below it is an 802.3 length (IEEE 802.3 3.2.6).
const ethernetTypeMinValue = 0x0600

// Dot1Q is the packet layer for 802.1Q VLAN headers.
type Dot1Q struct {
	BaseLayer
	Priority       uint8
	DropEligible   bool
	VLANIdentifier uint16
	Type           EthernetType
}

// LayerType returns gopacket.LayerTypeDot1Q
func (d *Dot1Q) LayerType() gopacket.LayerType { return LayerTypeDot1Q }

// DecodeFromBytes decodes the given bytes into this layer.
func (d *Dot1Q) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return fmt.Errorf("802.1Q tag length %d too short", len(data))
	}
	d.Priority = (data[0] & 0xE0) >> 5
	d.DropEligible = data[0]&0x10 != 0
	d.VLANIdentifier = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
	d.Type = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	d.BaseLayer = BaseLayer{Contents: data[:4], Payload: data[4:]}
	if d.Type < ethernetTypeMinValue {
		// An 802.3 length rather than an EtherType, as in Ethernet: an LLC
		// header follows and the payload ends after that many bytes.
		if len(d.Payload) < int(d.Type) {
			df.SetTruncated()
		} else {
			d.Payload = d.Payload[:d.Type]
		}
	}
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (d *Dot1Q) CanDecode() gopacket.LayerClass {
	return LayerTypeDot1Q
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (d *Dot1Q) NextLayerType() gopacket.LayerType {
	if d.Type < ethernetTypeMinValue {
		// 802.3 length field, see DecodeFromBytes.
		return LayerTypeLLC
	}
	return d.Type.LayerType()
}

func decodeDot1Q(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot1Q{}
	return decodingLayerDecoder(d, data, p)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (d *Dot1Q) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	if d.VLANIdentifier > 0xFFF {
		return fmt.Errorf("vlan identifier %v is too high", d.VLANIdentifier)
	}
	firstBytes := uint16(d.Priority)<<13 | d.VLANIdentifier
	if d.DropEligible {
		firstBytes |= 0x1000
	}
	binary.BigEndian.PutUint16(bytes, firstBytes)
	binary.BigEndian.PutUint16(bytes[2:], uint16(d.Type))
	return nil
}
