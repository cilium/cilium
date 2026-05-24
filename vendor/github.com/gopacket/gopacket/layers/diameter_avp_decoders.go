package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// decodeDiameterAVP decodes a single AVP and returns it along with bytes consumed
func decodeDiameterAVP(data []byte) (DiameterAVP, int, error) {
	if len(data) < 8 {
		return DiameterAVP{}, 0, errors.New("AVP too short")
	}

	avp := DiameterAVP{}

	// AVP Code (bytes 0-3)
	avp.Code = binary.BigEndian.Uint32(data[0:4])

	// AVP Flags (byte 4)
	avp.Flags.Vendor = (data[4] & 0x80) != 0
	avp.Flags.Mandatory = (data[4] & 0x40) != 0
	avp.Flags.Protected = (data[4] & 0x20) != 0

	// AVP Length is 24 bits (bytes 5-7)
	avp.Length = uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	if avp.Length < 8 {
		return DiameterAVP{}, 0, fmt.Errorf("invalid AVP length: %d", avp.Length)
	}

	headerSize := 8
	dataOffset := 8

	// Vendor ID (optional, present if Vendor flag is set)
	if avp.Flags.Vendor {
		if len(data) < 12 {
			return DiameterAVP{}, 0, errors.New("AVP with vendor flag too short")
		}
		avp.VendorID = binary.BigEndian.Uint32(data[8:12])
		headerSize = 12
		dataOffset = 12
	}

	// Calculate padding (AVPs are padded to 4-byte boundaries)
	paddedLength := avp.Length
	if avp.Length%4 != 0 {
		paddedLength = avp.Length + (4 - avp.Length%4)
	}

	if uint32(len(data)) < paddedLength {
		return DiameterAVP{}, 0, fmt.Errorf("AVP data truncated: expected %d bytes, got %d", paddedLength, len(data))
	}

	// Extract AVP data
	dataLength := avp.Length - uint32(headerSize)
	avp.Data = make([]byte, dataLength)
	copy(avp.Data, data[dataOffset:dataOffset+int(dataLength)])

	// Check if this is a Grouped AVP and decode sub-AVPs
	// Use vendor-aware type detection
	if avpType, ok := GetDiameterAVPType(avp.Code, avp.VendorID); ok && avpType == DiameterAVPTypeGrouped {
		avp.GroupedAVPs = []DiameterAVP{}
		subAVPData := avp.Data
		for len(subAVPData) >= 8 {
			subAVP, consumed, err := decodeDiameterAVP(subAVPData)
			if err != nil {
				break
			}
			avp.GroupedAVPs = append(avp.GroupedAVPs, subAVP)
			subAVPData = subAVPData[consumed:]
		}
	}

	return avp, int(paddedLength), nil
}

// ParseDiameterAVPs parses all AVPs from a data slice
func ParseDiameterAVPs(data []byte) ([]DiameterAVP, error) {
	avps := []DiameterAVP{}

	for len(data) >= 8 {
		avp, bytesConsumed, err := decodeDiameterAVP(data)
		if err != nil {
			return avps, err
		}
		avps = append(avps, avp)
		data = data[bytesConsumed:]
	}

	return avps, nil
}

// SerializeDiameterAVP serializes a Diameter AVP to bytes
func SerializeDiameterAVP(avp *DiameterAVP) []byte {
	headerSize := 8
	if avp.Flags.Vendor {
		headerSize = 12
	}

	length := headerSize + len(avp.Data)
	paddedLength := length
	if length%4 != 0 {
		paddedLength = length + (4 - length%4)
	}

	bytes := make([]byte, paddedLength)

	// AVP Code
	binary.BigEndian.PutUint32(bytes[0:4], avp.Code)

	// AVP Flags
	bytes[4] = 0
	if avp.Flags.Vendor {
		bytes[4] |= 0x80
	}
	if avp.Flags.Mandatory {
		bytes[4] |= 0x40
	}
	if avp.Flags.Protected {
		bytes[4] |= 0x20
	}

	// AVP Length (24 bits)
	bytes[5] = byte(length >> 16)
	bytes[6] = byte(length >> 8)
	bytes[7] = byte(length)

	// Vendor ID (if present)
	if avp.Flags.Vendor {
		binary.BigEndian.PutUint32(bytes[8:12], avp.VendorID)
		copy(bytes[12:], avp.Data)
	} else {
		copy(bytes[8:], avp.Data)
	}

	return bytes
}

// SerializedAVPLength returns the length of the AVP when serialized
func SerializedAVPLength(avp *DiameterAVP) int {
	headerSize := 8
	if avp.Flags.Vendor {
		headerSize = 12
	}
	length := headerSize + len(avp.Data)
	// Pad to 4-byte boundary
	if length%4 != 0 {
		length += 4 - (length % 4)
	}
	return length
}
