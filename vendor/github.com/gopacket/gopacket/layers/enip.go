// Copyright 2018, The GoPacket Authors, All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
//******************************************************************************

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

//******************************************************************************
//
// ENIP (Ethernet/IP) Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for ENIP (Ethernet/IP).
// Ethernet/IP is an industrial protocol that encapsulates CIP (Common Industrial Protocol)
//
//******************************************************************************

const enipHeaderSize = 24

// ENIPCommand represents the command code in an ENIP packet
type ENIPCommand uint16

// ENIP Command codes
const (
	ENIPCommandNOP               ENIPCommand = 0x0000
	ENIPCommandListServices      ENIPCommand = 0x0004
	ENIPCommandListIdentity      ENIPCommand = 0x0063
	ENIPCommandListInterfaces    ENIPCommand = 0x0064
	ENIPCommandRegisterSession   ENIPCommand = 0x0065
	ENIPCommandUnregisterSession ENIPCommand = 0x0066
	ENIPCommandSendRRData        ENIPCommand = 0x006F
	ENIPCommandSendUnitData      ENIPCommand = 0x0070
	ENIPCommandIndicateStatus    ENIPCommand = 0x0072
	ENIPCommandCancel            ENIPCommand = 0x0073
)

func (ec ENIPCommand) String() string {
	switch ec {
	case ENIPCommandNOP:
		return "NOP"
	case ENIPCommandListServices:
		return "ListServices"
	case ENIPCommandListIdentity:
		return "ListIdentity"
	case ENIPCommandListInterfaces:
		return "ListInterfaces"
	case ENIPCommandRegisterSession:
		return "RegisterSession"
	case ENIPCommandUnregisterSession:
		return "UnregisterSession"
	case ENIPCommandSendRRData:
		return "SendRRData"
	case ENIPCommandSendUnitData:
		return "SendUnitData"
	case ENIPCommandIndicateStatus:
		return "IndicateStatus"
	case ENIPCommandCancel:
		return "Cancel"
	default:
		return fmt.Sprintf("Unknown Command (0x%04x)", uint16(ec))
	}
}

// ENIPStatus represents the status code in an ENIP packet
type ENIPStatus uint32

// ENIP Status codes
const (
	ENIPStatusSuccess              ENIPStatus = 0x0000
	ENIPStatusInvalidCommand       ENIPStatus = 0x0001
	ENIPStatusInsufficientMemory   ENIPStatus = 0x0002
	ENIPStatusIncorrectData        ENIPStatus = 0x0003
	ENIPStatusInvalidSessionHandle ENIPStatus = 0x0064
	ENIPStatusInvalidLength        ENIPStatus = 0x0065
	ENIPStatusUnsupportedProtocol  ENIPStatus = 0x0069
)

func (es ENIPStatus) String() string {
	switch es {
	case ENIPStatusSuccess:
		return "Success"
	case ENIPStatusInvalidCommand:
		return "Invalid Command"
	case ENIPStatusInsufficientMemory:
		return "Insufficient Memory"
	case ENIPStatusIncorrectData:
		return "Incorrect Data"
	case ENIPStatusInvalidSessionHandle:
		return "Invalid Session Handle"
	case ENIPStatusInvalidLength:
		return "Invalid Length"
	case ENIPStatusUnsupportedProtocol:
		return "Unsupported Protocol"
	default:
		return fmt.Sprintf("Unknown Status (0x%08x)", uint32(es))
	}
}

//******************************************************************************

// ENIP represents an Ethernet/IP packet
type ENIP struct {
	BaseLayer

	Command       ENIPCommand // Command code
	Length        uint16      // Length of data portion in bytes
	SessionHandle uint32      // Session identification
	Status        ENIPStatus  // Status code
	SenderContext uint64      // Sender context
	Options       uint32      // Options flags
}

//******************************************************************************

// LayerType returns the layer type of the ENIP object
func (e *ENIP) LayerType() gopacket.LayerType {
	return LayerTypeENIP
}

//******************************************************************************

// decodeENIP analyses a byte slice and attempts to decode it as an ENIP packet
func decodeENIP(data []byte, p gopacket.PacketBuilder) error {
	enip := &ENIP{}
	err := enip.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(enip)
	p.SetApplicationLayer(enip)
	return p.NextDecoder(enip.NextLayerType())
}

//******************************************************************************

// DecodeFromBytes analyses a byte slice and attempts to decode it as an ENIP packet
func (e *ENIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < enipHeaderSize {
		df.SetTruncated()
		return errors.New("ENIP packet too short")
	}

	// Parse ENIP header
	e.Command = ENIPCommand(binary.LittleEndian.Uint16(data[0:2]))
	e.Length = binary.LittleEndian.Uint16(data[2:4])
	e.SessionHandle = binary.LittleEndian.Uint32(data[4:8])
	e.Status = ENIPStatus(binary.LittleEndian.Uint32(data[8:12]))

	// Sender context is 8 bytes at offset 12
	e.SenderContext = binary.LittleEndian.Uint64(data[12:20])

	e.Options = binary.LittleEndian.Uint32(data[20:24])

	// Check if we have enough data for the payload
	totalLength := enipHeaderSize + int(e.Length)
	if len(data) < totalLength {
		df.SetTruncated()
		return fmt.Errorf("ENIP packet truncated: expected %d bytes, got %d", totalLength, len(data))
	}

	e.BaseLayer = BaseLayer{
		Contents: data[:enipHeaderSize],
		Payload:  data[enipHeaderSize:totalLength],
	}

	return nil
}

//******************************************************************************

// NextLayerType returns the layer type of the ENIP payload
// For SendRRData and SendUnitData commands, the payload typically contains CIP data
func (e *ENIP) NextLayerType() gopacket.LayerType {
	// Commands that typically contain CIP data
	switch e.Command {
	case ENIPCommandSendRRData, ENIPCommandSendUnitData:
		// The payload contains CIP encapsulation, but we'll simplify and try to decode as CIP
		// In reality, SendRRData and SendUnitData have additional encapsulation headers
		// For now, we'll just return CIP and let it handle what it can
		if len(e.Payload()) > 0 {
			return LayerTypeCIP
		}
	}
	return gopacket.LayerTypePayload
}

//******************************************************************************

// Payload returns the ENIP payload bytes
func (e *ENIP) Payload() []byte {
	return e.BaseLayer.Payload
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (e *ENIP) CanDecode() gopacket.LayerClass {
	return LayerTypeENIP
}

// SerializeTo writes the serialized form of this layer into the SerializationBuffer
func (e *ENIP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(enipHeaderSize)
	if err != nil {
		return err
	}

	binary.LittleEndian.PutUint16(bytes[0:2], uint16(e.Command))

	if opts.FixLengths {
		e.Length = uint16(len(b.Bytes()) - enipHeaderSize)
	}
	binary.LittleEndian.PutUint16(bytes[2:4], e.Length)

	binary.LittleEndian.PutUint32(bytes[4:8], e.SessionHandle)
	binary.LittleEndian.PutUint32(bytes[8:12], uint32(e.Status))
	binary.LittleEndian.PutUint64(bytes[12:20], e.SenderContext)
	binary.LittleEndian.PutUint32(bytes[20:24], e.Options)

	return nil
}
