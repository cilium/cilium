// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

type STPSwitchID struct {
	Priority uint16 // Bridge priority
	SysID    uint16 // VLAN ID
	HwAddr   net.HardwareAddr
}

// STP decode spanning tree protocol packets to transport BPDU (bridge protocol data unit) message.
type STP struct {
	BaseLayer
	ProtocolID        uint16
	Version           uint8
	Type              uint8
	TC, TCA           bool // TC: Topologie change ; TCA: Topologie change ack
	RouteID, BridgeID STPSwitchID
	Cost              uint32
	PortID            uint16
	MessageAge        uint16
	MaxAge            uint16
	HelloTime         uint16
	FDelay            uint16
}

// LayerType returns gopacket.LayerTypeSTP.
func (s *STP) LayerType() gopacket.LayerType { return LayerTypeSTP }

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (s *STP) CanDecode() gopacket.LayerClass {
	return LayerTypeSTP
}

// DecodeFromBytes decodes the given bytes into this layer.
func (stp *STP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	stpLength := 35
	if len(data) < stpLength {
		df.SetTruncated()
		return fmt.Errorf("STP length %d too short", len(data))
	}

	stp.ProtocolID = binary.BigEndian.Uint16(data[:2])
	stp.Version = uint8(data[2])
	stp.Type = uint8(data[3])
	stp.TC = data[4]&0x01 != 0
	stp.TCA = data[4]&0x80 != 0
	stp.RouteID.Priority = binary.BigEndian.Uint16(data[5:7]) & 0xf000
	stp.RouteID.SysID = binary.BigEndian.Uint16(data[5:7]) & 0x0fff
	stp.RouteID.HwAddr = net.HardwareAddr(data[7:13])
	stp.Cost = binary.BigEndian.Uint32(data[13:17])
	stp.BridgeID.Priority = binary.BigEndian.Uint16(data[17:19]) & 0xf000
	stp.BridgeID.SysID = binary.BigEndian.Uint16(data[17:19]) & 0x0fff
	stp.BridgeID.HwAddr = net.HardwareAddr(data[19:25])
	stp.PortID = binary.BigEndian.Uint16(data[25:27])
	stp.MessageAge = binary.BigEndian.Uint16(data[27:29])
	stp.MaxAge = binary.BigEndian.Uint16(data[29:31])
	stp.HelloTime = binary.BigEndian.Uint16(data[31:33])
	stp.FDelay = binary.BigEndian.Uint16(data[33:35])
	stp.Contents = data[:stpLength]
	stp.Payload = data[stpLength:]

	return nil
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (stp *STP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Check if the priority value is correct.
func checkPriority(prio uint16) (uint16, error) {
	if prio == 0 {
		return prio, errors.New("Invalid Priority value must be in the rage <4096-61440> with an increment of 4096")
	}
	if prio%4096 == 0 {
		return prio, nil
	} else {
		return prio, errors.New("Invalid Priority value must be in the rage <4096-61440> with an increment of 4096")
	}
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (s *STP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var flags uint8 = 0x00
	bytes, err := b.PrependBytes(35)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, s.ProtocolID)
	bytes[2] = s.Version
	bytes[3] = s.Type
	if s.TC {
		flags |= 0x01
	}
	if s.TCA {
		flags |= 0x80
	}
	bytes[4] = flags

	prioRoot, err := checkPriority(s.RouteID.Priority)
	if err != nil {
		panic(err)
	}
	if s.RouteID.SysID >= 4096 {
		panic("Invalid VlanID value ..!")
	}
	binary.BigEndian.PutUint16(bytes[5:7], prioRoot|s.RouteID.SysID)
	copy(bytes[7:13], s.RouteID.HwAddr)

	binary.BigEndian.PutUint32(bytes[13:17], s.Cost)

	prioBridge, err := checkPriority(s.BridgeID.Priority)
	if err != nil {
		panic(err)
	}
	if s.BridgeID.SysID >= 4096 {
		panic("Invalid VlanID value ..!")
	}
	binary.BigEndian.PutUint16(bytes[17:19], prioBridge|s.BridgeID.SysID)
	copy(bytes[19:25], s.BridgeID.HwAddr)

	binary.BigEndian.PutUint16(bytes[25:27], s.PortID)
	binary.BigEndian.PutUint16(bytes[27:29], s.MessageAge)
	binary.BigEndian.PutUint16(bytes[29:31], s.MaxAge)
	binary.BigEndian.PutUint16(bytes[31:33], s.HelloTime)
	binary.BigEndian.PutUint16(bytes[33:35], s.FDelay)

	return nil
}

func decodeSTP(data []byte, p gopacket.PacketBuilder) error {
	stp := &STP{}
	return decodingLayerDecoder(stp, data, p)
}
