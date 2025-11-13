// Copyright 2025 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// This file implements the Andromeda PSP header, a specialized version of the PSP header.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// APSP represents a packet encrypted with the Andromeda Paddywhack Security Protocol.
// It should sit "under" a UDP layer with dest port 1000.
// For more information about the meaning of the fields,
// see go/andromeda-psp-format
// This is a remix and extension of the basic PSP header, see go/psp-format
// Field order and packing don't really matter, because we serialize explicitly,
// in SerializeTo()
type APSP struct {
	BaseLayer
	NextHeader    uint8
	HdrExtLen     uint8
	CryptOffset   uint8 // lower 6 bits are offset, 2 high bits are reserved
	SDVersVirt    uint8 // see go/andromeda-psp-format for bitfield breakdown
	SecParamIdx   uint32
	InitVector    uint64
	SecTokenV2    uint32
	VirtKey       uint32
	SrcEndpointID uint64
	DstEndpointID uint64
}

// ApspLen is the sum of the header fields above, by length
const ApspLen = 40

// CanDecode returns the type of layer we can decode.
func (l APSP) CanDecode() gopacket.LayerClass {
	return LayerTypeAPSP
}

// DecodeFromBytes extracts our header data from a serialized packet.
func (l *APSP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < ApspLen {
		df.SetTruncated()
		return fmt.Errorf("invalid APSP header. Length %d less than %d", len(data), ApspLen)
	}
	l.NextHeader = data[0]
	l.HdrExtLen = data[1]
	l.CryptOffset = data[2]
	l.SDVersVirt = data[3]
	l.SecParamIdx = binary.BigEndian.Uint32(data[4:8])
	l.InitVector = binary.BigEndian.Uint64(data[8:16])
	l.SecTokenV2 = binary.BigEndian.Uint32(data[16:20])
	l.VirtKey = binary.BigEndian.Uint32(data[20:24])
	l.SrcEndpointID = binary.BigEndian.Uint64(data[24:32])
	l.DstEndpointID = binary.BigEndian.Uint64(data[32:40])
	l.BaseLayer = BaseLayer{Contents: data[:ApspLen]}
	l.Payload = data[ApspLen:]
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (l APSP) SerializeTo(buf gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	b := l.LayerContents()
	writeTo, err := buf.PrependBytes(len(b))
	if err != nil {
		return err
	}
	copy(writeTo, b)
	return nil
}

// LayerContents returns a byte array containing our serialized header.
func (l APSP) LayerContents() []byte {
	bytes := make([]byte, ApspLen)
	bytes[0] = l.NextHeader
	bytes[1] = l.HdrExtLen
	bytes[2] = l.CryptOffset
	bytes[3] = l.SDVersVirt
	binary.BigEndian.PutUint32(bytes[4:], l.SecParamIdx)
	binary.BigEndian.PutUint64(bytes[8:], l.InitVector)
	binary.BigEndian.PutUint32(bytes[16:], l.SecTokenV2)
	binary.BigEndian.PutUint32(bytes[20:], l.VirtKey)
	binary.BigEndian.PutUint64(bytes[24:], l.SrcEndpointID)
	binary.BigEndian.PutUint64(bytes[32:], l.DstEndpointID)
	return bytes
}

// LayerPayload returns an IPv4 or IPv6 packet in serialized form.
func (l APSP) LayerPayload() []byte {
	return l.Payload
}

// NextLayerType returns the next layer type, either IPv4 or IPv6.
func (l APSP) NextLayerType() gopacket.LayerType {
	// TODO: check for IPv6
	return LayerTypeIPv4
}

// LayerType returns LayerTypeAPSP.
func (l APSP) LayerType() gopacket.LayerType {
	return LayerTypeAPSP
}

func decodeAPSP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) == 0 {
		return errors.New("decodeAPSP() failed, no data")
	}
	l := APSP{}
	if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	p.AddLayer(l)
	return p.NextDecoder(l.NextLayerType())
}
