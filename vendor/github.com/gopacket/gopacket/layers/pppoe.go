// Copyright 2012 Google, Inc. All rights reserved.
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

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	BaseLayer
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionId uint16
	Length    uint16
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoE) LayerType() gopacket.LayerType {
	return LayerTypePPPoE
}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516)
// and lets the Code select the next layer.
func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {
	pppoe, err := decodePPPoEHeader(data, p)
	if err != nil {
		return err
	}
	return p.NextDecoder(pppoe.Code)
}

// decodePPPoESession decodes a session stage packet (EtherType 0x8864). The
// EtherType alone makes it one: a receiver hands the payload to PPP without
// looking at the Code, so a non-zero Code must not hide the payload.
func decodePPPoESession(data []byte, p gopacket.PacketBuilder) error {
	if _, err := decodePPPoEHeader(data, p); err != nil {
		return err
	}
	return p.NextDecoder(LayerTypePPP)
}

// decodePPPoEHeader decodes the PPPoE header and adds it to the packet,
// leaving the choice of the next decoder to the caller.
func decodePPPoEHeader(data []byte, p gopacket.PacketBuilder) (*PPPoE, error) {
	if len(data) < 6 {
		p.SetTruncated()
		return nil, fmt.Errorf("PPPoE packet length %d too short", len(data))
	}
	pppoe := &PPPoE{
		Version:   data[0] >> 4,
		Type:      data[0] & 0x0F,
		Code:      PPPoECode(data[1]),
		SessionId: binary.BigEndian.Uint16(data[2:4]),
		Length:    binary.BigEndian.Uint16(data[4:6]),
	}
	payloadEnd := 6 + int(pppoe.Length)
	if len(data) < payloadEnd {
		p.SetTruncated()
		return nil, fmt.Errorf("PPPoE packet length %d too short, %d total bytes expected", len(data), payloadEnd)
	}
	pppoe.BaseLayer = BaseLayer{data[:6], data[6:payloadEnd]}
	p.AddLayer(pppoe)
	return pppoe, nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPPoE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return err
	}
	bytes[0] = (p.Version << 4) | p.Type
	bytes[1] = byte(p.Code)
	binary.BigEndian.PutUint16(bytes[2:], p.SessionId)
	if opts.FixLengths {
		p.Length = uint16(len(payload))
	}
	binary.BigEndian.PutUint16(bytes[4:], p.Length)
	return nil
}
