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

	for {
		if offset >= m.Length {
			break
		}
		t := data[offset]
		switch t {
		case MdpTlvDeviceInfo:
			offset += 2
			length = int(data[offset-1])
			m.Contents = append(m.Contents, data[offset-2:offset+length]...)
			m.DeviceInfo = string(data[offset : offset+length])
			offset += length
			break
		case MdpTlvNetworkInfo:
			offset += 2
			length = int(data[offset-1])
			m.NetworkInfo = string(data[offset : offset+length])
			offset += length
			break
		case MdpTlvLongitude:
			offset += 2
			length = int(data[offset-1])
			m.Longitude, _ = strconv.ParseFloat(string(data[offset:offset+length]), 64)
			offset += length
			break
		case MdpTlvLatitude:
			offset += 2
			length = int(data[offset-1])
			m.Latitude, _ = strconv.ParseFloat(string(data[offset:offset+length]), 64)
			offset += length
			break
		case MdpTlvType6:
			offset += 2
			length = int(data[offset-1])
			m.Type6UUID = string(data[offset : offset+length])
			offset += length
			break
		case MdpTlvType7:
			offset += 2
			length = int(data[offset-1])
			m.Type7UUID = string(data[offset : offset+length])
			offset += length
			break
		case MdpTlvIP:
			offset += 2
			length = int(data[offset-1])
			m.IPAddress = net.ParseIP(string(data[offset : offset+length]))
			offset += length
			break
		case MdpTlvUnknownBool:
			offset += 2
			length = int(data[offset-1])
			m.Type13Bool, _ = strconv.ParseBool(string(data[offset : offset+length]))
			offset += length
			break
		case MdpTlvEnd:
			offset = m.Length
			break
		default:
			// Skip over unknown junk
			offset += 2
			length = int(data[offset-1])
			offset += length
			break

		}
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
