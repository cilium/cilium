// Copyright 2024 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
)

const (
	MdpTlvType uint8 = iota
	MdpTlvLength
	MdpTlvDeviceInfo
	MdpTlvNetworkInfo
	MdpTlvLongitude
	MdpTlvLatitude
	MdpTlvType6
	MdpTlvType7
	MdpTlvIP          = 11
	MdpTlvUnknownBool = 13
	MdpTlvEnd         = 255
)

// MDP defines a MDP over LLC layer.
type MDP struct {
	BaseLayer
	PreambleData []byte
	DeviceInfo   string
	NetworkInfo  string
	Longitude    float64
	Latitude     float64
	Type6UUID    string
	Type7UUID    string
	IPAddress    net.IP
	Type13Bool   bool

	Type   EthernetType
	Length int
}

// LayerType returns LayerTypeMDP.
func (m *MDP) LayerType() gopacket.LayerType { return LayerTypeMDP }

// DecodeFromBytes decodes the given bytes into this layer.
func (m *MDP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var length int
	if len(data) < 28 {
		df.SetTruncated()
		return fmt.Errorf("MDP length %d too short", len(data))
	}
	m.Type = EthernetTypeMerakiDiscoveryProtocol
	m.Length = len(data)
	offset := 28
	m.PreambleData = data[:offset]

	// Each TLV is <type><length><value>; both header bytes and the value are
	// bounded against the frame before use.
	for offset < m.Length {
		t := data[offset]
		if t == MdpTlvEnd {
			break
		}
		if offset+2 > m.Length {
			df.SetTruncated()
			return fmt.Errorf("MDP TLV %d header truncated at offset %d", t, offset)
		}
		length = int(data[offset+1])
		if offset+2+length > m.Length {
			df.SetTruncated()
			return fmt.Errorf("MDP TLV %d length %d exceeds frame at offset %d", t, length, offset)
		}
		value := data[offset+2 : offset+2+length]

		switch t {
		case MdpTlvDeviceInfo:
			m.Contents = append(m.Contents, data[offset:offset+2+length]...)
			m.DeviceInfo = string(value)
		case MdpTlvNetworkInfo:
			m.NetworkInfo = string(value)
		case MdpTlvLongitude:
			m.Longitude, _ = strconv.ParseFloat(string(value), 64)
		case MdpTlvLatitude:
			m.Latitude, _ = strconv.ParseFloat(string(value), 64)
		case MdpTlvType6:
			m.Type6UUID = string(value)
		case MdpTlvType7:
			m.Type7UUID = string(value)
		case MdpTlvIP:
			m.IPAddress = net.ParseIP(string(value))
		case MdpTlvUnknownBool:
			m.Type13Bool, _ = strconv.ParseBool(string(value))
		default:
			// Skip over unknown junk
		}
		offset += 2 + length
	}
	m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer
func (m *MDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// bytes, _ := b.PrependBytes(4)
	// bytes[0] = m.Version
	// bytes[1] = byte(m.Type)
	// binary.BigEndian.PutUint16(bytes[2:], m.Length)
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (m *MDP) CanDecode() gopacket.LayerClass {
	return LayerTypeMDP
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (m *MDP) NextLayerType() gopacket.LayerType {
	return m.Type.LayerType()
}

func decodeMDP(data []byte, p gopacket.PacketBuilder) error {
	m := &MDP{}
	err := m.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(m)
	return p.NextDecoder(m.NextLayerType())
}
