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
// CIP (Common Industrial Protocol) Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for CIP.
//
//******************************************************************************

// CIPService represents the service code in a CIP request/response
type CIPService uint8

// Common CIP Service codes
const (
	CIPServiceGetAttributesAll      CIPService = 0x01
	CIPServiceSetAttributesAll      CIPService = 0x02
	CIPServiceGetAttributeSingle    CIPService = 0x0E
	CIPServiceSetAttributeSingle    CIPService = 0x10
	CIPServiceMultipleServicePacket CIPService = 0x0A
)

func (cs CIPService) String() string {
	switch cs {
	case CIPServiceGetAttributesAll:
		return "Get Attributes All"
	case CIPServiceSetAttributesAll:
		return "Set Attributes All"
	case CIPServiceGetAttributeSingle:
		return "Get Attribute Single"
	case CIPServiceSetAttributeSingle:
		return "Set Attribute Single"
	case CIPServiceMultipleServicePacket:
		return "Multiple Service Packet"
	default:
		return fmt.Sprintf("Unknown Service (0x%02x)", uint8(cs))
	}
}

// CIPStatus represents the status code in a CIP response
type CIPStatus uint8

// Common CIP Status codes
const (
	CIPStatusSuccess                CIPStatus = 0x00
	CIPStatusConnectionFailure      CIPStatus = 0x01
	CIPStatusResourceUnavailable    CIPStatus = 0x02
	CIPStatusInvalidParameterValue  CIPStatus = 0x03
	CIPStatusPathSegmentError       CIPStatus = 0x04
	CIPStatusPathDestinationUnknown CIPStatus = 0x05
	CIPStatusPartialTransfer        CIPStatus = 0x06
	CIPStatusConnectionLost         CIPStatus = 0x07
	CIPStatusServiceNotSupported    CIPStatus = 0x08
	CIPStatusInvalidAttributeValue  CIPStatus = 0x09
)

func (cs CIPStatus) String() string {
	switch cs {
	case CIPStatusSuccess:
		return "Success"
	case CIPStatusConnectionFailure:
		return "Connection Failure"
	case CIPStatusResourceUnavailable:
		return "Resource Unavailable"
	case CIPStatusInvalidParameterValue:
		return "Invalid Parameter Value"
	case CIPStatusPathSegmentError:
		return "Path Segment Error"
	case CIPStatusPathDestinationUnknown:
		return "Path Destination Unknown"
	case CIPStatusPartialTransfer:
		return "Partial Transfer"
	case CIPStatusConnectionLost:
		return "Connection Lost"
	case CIPStatusServiceNotSupported:
		return "Service Not Supported"
	case CIPStatusInvalidAttributeValue:
		return "Invalid Attribute Value"
	default:
		return fmt.Sprintf("Unknown Status (0x%02x)", uint8(cs))
	}
}

//******************************************************************************

// CIP represents a Common Industrial Protocol packet
type CIP struct {
	BaseLayer

	Service          CIPService // Service code
	Response         bool       // true if this is a response, false if request
	PathSize         uint8      // Size of path in words (16-bit)
	ClassID          *uint32    // Class ID if present in path
	InstanceID       *uint32    // Instance ID if present in path
	AttributeID      *uint32    // Attribute ID if present in path
	Status           CIPStatus  // Status code (response only)
	AdditionalStatus []uint8    // Additional status bytes (response only)
}

//******************************************************************************

// LayerType returns the layer type of the CIP object
func (c *CIP) LayerType() gopacket.LayerType {
	return LayerTypeCIP
}

//******************************************************************************

// decodeCIP analyses a byte slice and attempts to decode it as a CIP packet
func decodeCIP(data []byte, p gopacket.PacketBuilder) error {
	c := &CIP{}
	err := c.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(c)
	p.SetApplicationLayer(c)
	return p.NextDecoder(c.NextLayerType())
}

//******************************************************************************

// DecodeFromBytes analyses a byte slice and attempts to decode it as a CIP packet
func (c *CIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 2 {
		df.SetTruncated()
		return errors.New("CIP packet too short")
	}

	// First byte is service code
	// Bit 7 indicates if this is a response (1) or request (0)
	c.Service = CIPService(data[0] & 0x7F)
	c.Response = (data[0] & 0x80) != 0

	offset := 1

	if c.Response {
		// Response packet structure
		if len(data) < 4 {
			df.SetTruncated()
			return errors.New("CIP response packet too short")
		}
		// Reserved byte
		offset++

		// Status
		c.Status = CIPStatus(data[offset])
		offset++

		// Additional status size
		additionalStatusSize := int(data[offset])
		offset++

		// Additional status bytes
		if additionalStatusSize > 0 {
			if len(data) < offset+additionalStatusSize*2 {
				df.SetTruncated()
				return errors.New("CIP response packet truncated in additional status")
			}
			c.AdditionalStatus = data[offset : offset+additionalStatusSize*2]
			offset += additionalStatusSize * 2
		}
	} else {
		// Request packet structure
		// Path size in words
		c.PathSize = data[offset]
		offset++

		pathBytes := int(c.PathSize) * 2
		if len(data) < offset+pathBytes {
			df.SetTruncated()
			return errors.New("CIP request packet truncated in path")
		}

		// Parse path segments (simplified - only handle logical segments)
		pathData := data[offset : offset+pathBytes]
		c.parsePath(pathData)
		offset += pathBytes
	}

	c.BaseLayer = BaseLayer{
		Contents: data[:offset],
		Payload:  data[offset:],
	}

	return nil
}

//******************************************************************************

// parsePath parses CIP path segments (simplified implementation)
func (c *CIP) parsePath(data []byte) {
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		segmentType := data[offset]

		// Logical segment (0x20 series)
		if segmentType&0xE0 == 0x20 {
			logicalType := (segmentType >> 2) & 0x07
			logicalFormat := segmentType & 0x03

			var value uint32
			var size int

			switch logicalFormat {
			case 0: // 8-bit
				if offset+2 <= len(data) {
					value = uint32(data[offset+1])
					size = 2
				}
			case 1: // 16-bit
				if offset+4 <= len(data) {
					value = uint32(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
					size = 4
				}
			case 2: // 32-bit
				if offset+6 <= len(data) {
					value = binary.LittleEndian.Uint32(data[offset+2 : offset+6])
					size = 6
				}
			default:
				return
			}

			switch logicalType {
			case 0: // Class ID
				c.ClassID = &value
			case 1: // Instance ID
				c.InstanceID = &value
			case 4: // Attribute ID
				c.AttributeID = &value
			}

			offset += size
		} else {
			// Unknown segment type, skip
			offset += 2
		}
	}
}

//******************************************************************************

// NextLayerType returns the layer type of the CIP payload
func (c *CIP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

//******************************************************************************

// Payload returns the CIP payload bytes
func (c *CIP) Payload() []byte {
	return c.BaseLayer.Payload
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (c *CIP) CanDecode() gopacket.LayerClass {
	return LayerTypeCIP
}
