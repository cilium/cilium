// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
)

// IPSecAH is the authentication header for IPv4/6 defined in
// http://tools.ietf.org/html/rfc2402
type IPSecAH struct {
	// While the auth header can be used for both IPv4 and v6, its format is that of
	// an IPv6 extension (NextHeader, PayloadLength, etc...), so we use ipv6ExtensionBase
	// to build it.
	ipv6ExtensionBase
	Reserved           uint16
	SPI, Seq           uint32
	AuthenticationData []byte
}

// LayerType returns LayerTypeIPSecAH.
func (i *IPSecAH) LayerType() gopacket.LayerType { return LayerTypeIPSecAH }

func decodeIPSecAH(data []byte, p gopacket.PacketBuilder) error {
	i := &IPSecAH{}
	return decodingLayerDecoder(i, data, p)
}

// DecodeFromBytes takes a byte buffer and decodes
func (i *IPSecAH) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 12 {
		df.SetTruncated()
		return errors.New("IPSec AH packet less than 12 bytes")
	}

	i.ipv6ExtensionBase = ipv6ExtensionBase{
		NextHeader:   IPProtocol(data[0]),
		HeaderLength: data[1],
	}

	i.Reserved = binary.BigEndian.Uint16(data[2:4])
	i.SPI = binary.BigEndian.Uint32(data[4:8])
	i.Seq = binary.BigEndian.Uint32(data[8:12])

	i.ActualLength = (int(i.HeaderLength) + 2) * 4
	if len(data) < i.ActualLength {
		df.SetTruncated()
		return errors.New("Truncated AH packet < ActualLength")
	}
	i.AuthenticationData = data[12:i.ActualLength]
	i.Contents = data[:i.ActualLength]
	i.Payload = data[i.ActualLength:]

	return nil
}

// CanDecode returns the layer type this DecodingLayer can decode
func (i *IPSecAH) CanDecode() gopacket.LayerClass {
	return LayerTypeIPSecAH
}

// NextLayerType returns the next layer we should see after IPSecAH
func (i *IPSecAH) NextLayerType() gopacket.LayerType {
	return i.NextHeader.LayerType()
}

// IPSecESP is the encapsulating security payload defined in
// http://tools.ietf.org/html/rfc2406
type IPSecESP struct {
	BaseLayer
	SPI, Seq uint32
	// Encrypted contains the encrypted set of bytes sent in an ESP
	Encrypted []byte
}

// LayerType returns LayerTypeIPSecESP.
func (i *IPSecESP) LayerType() gopacket.LayerType { return LayerTypeIPSecESP }

func decodeIPSecESP(data []byte, p gopacket.PacketBuilder) error {
	i := &IPSecESP{}
	return decodingLayerDecoder(i, data, p)
}

// DecodeFromBytes takes a byte buffer and decodes
func (i *IPSecESP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return errors.New("IPSec ESP packet less than 8 bytes")
	}

	i.BaseLayer = BaseLayer{data, nil}
	i.SPI = binary.BigEndian.Uint32(data[:4])
	i.Seq = binary.BigEndian.Uint32(data[4:8])
	i.Encrypted = data[8:]

	return nil
}

// CanDecode returns the layer type this DecodingLayer can decode
func (i *IPSecESP) CanDecode() gopacket.LayerClass {
	return LayerTypeIPSecESP
}

// NextLayerType retuns the next layer we should see after IPSecESP
func (i *IPSecESP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
