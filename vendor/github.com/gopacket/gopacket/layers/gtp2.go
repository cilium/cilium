package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/gopacket/gopacket"
)

const gtp2MinimumSizeInBytes int = 4

// gtp2Version is the only value of the 3-bit version field this decoder reads.
const gtp2Version uint8 = 2

// IE represents an Information Element in GTPv2, a key component for message structure
type IE struct {
	Type    uint8
	Content []byte
}

// GTPv2 is designed for the control plane of the Evolved Packet System,
// facilitating various control and mobility management messages between gateways and MME/S-GW.
// Defined in the 3GPP TS 29.274 specification
type GTPv2 struct {
	BaseLayer
	Version          uint8
	PiggybackingFlag bool
	TEIDflag         bool
	MessagePriority  uint8
	MessageType      uint8
	MessageLength    uint16
	TEID             uint32
	SequenceNumber   uint32
	Spare            uint8
	IEs              []IE
}

// DecodeFromBytes analyses a byte slice and attempts to decode it as a GTPv2 packet
func (g *GTPv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// start from a clean layer: DecodingLayerParser reuses one per packet
	*g = GTPv2{}

	hLen := gtp2MinimumSizeInBytes
	dLen := len(data)
	if dLen < hLen {
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}
	g.Version = (data[0] >> 5) & 0x07
	// GTPv1-C shares UDP port 2123 with GTPv2 but has a different header
	// and IE layout, so only version 2 can be read with this decoder.
	if g.Version != gtp2Version {
		return fmt.Errorf("GTPv2 packet has version %d", g.Version)
	}
	g.PiggybackingFlag = ((data[0] >> 4) & 0x01) == 1
	g.TEIDflag = ((data[0] >> 3) & 0x01) == 1
	g.MessagePriority = (data[0] >> 2) & 0x01
	g.MessageType = data[1]
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])

	// Message Length counts everything after the first 4 bytes. A packet may
	// carry more (a piggybacked message, padding); that is not part of this
	// message.
	mEnd := gtp2MinimumSizeInBytes + int(g.MessageLength)
	if dLen < mEnd {
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}

	cIndex := uint16(hLen)
	if g.TEIDflag {
		hLen += 4
		cIndex += 4
		if dLen < hLen {
			return fmt.Errorf("GTP packet too small: %d bytes", dLen)
		}
		g.TEID = binary.BigEndian.Uint32(data[4:8])
	}

	// SequenceNumber (3 bytes) is followed by the 1-byte Spare.
	if len(data) < int(cIndex)+4 {
		return fmt.Errorf("GTP packet too small for SequenceNumber: %d bytes", len(data))
	}
	g.SequenceNumber = uint32(data[cIndex])<<16 | uint32(data[cIndex+1])<<8 | uint32(data[cIndex+2])
	g.Spare = data[cIndex+3]
	hLen += 4
	cIndex += 4

	if mEnd < int(cIndex) {
		return fmt.Errorf("GTP message length %d does not cover the header", g.MessageLength)
	}

	for int(cIndex) < mEnd {
		// Need the full 4-byte IE header; int arithmetic so a 16-bit length
		// cannot wrap past the bound.
		if int(cIndex)+4 > mEnd {
			return fmt.Errorf("GTPv2 IE header truncated at offset %d", cIndex)
		}
		ieType := data[cIndex]
		ieLength := int(binary.BigEndian.Uint16(data[cIndex+1 : cIndex+3]))
		ieEnd := int(cIndex) + 4 + ieLength
		if ieEnd > mEnd {
			return fmt.Errorf("IE %d exceeds message length", ieType)
		}
		ieContent := data[int(cIndex)+4 : ieEnd]
		g.IEs = append(g.IEs, IE{Type: ieType, Content: ieContent})
		cIndex = uint16(ieEnd)
	}

	g.BaseLayer = BaseLayer{Contents: data[:cIndex], Payload: data[cIndex:]}
	return nil

}

// decodeGTPv2 is a utility function to facilitate the decoding of GTPv2 packets within GoPacket's framework
func decodeGTPv2(data []byte, p gopacket.PacketBuilder) error {
	gtp := &GTPv2{}

	if err := gtp.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(gtp)
	return p.NextDecoder(gtp.NextLayerType())
}

// LayerType returns LayerTypeGTPv2
func (g *GTPv2) LayerType() gopacket.LayerType {
	return LayerTypeGTPv2
}

// LayerContents returns the contents of the GTPv2 layer.
func (g *GTPv2) LayerContents() []byte {
	return g.Contents
}

// LayerPayload returns the payload of the GTPv2 layer.
func (g *GTPv2) LayerPayload() []byte {
	return g.Payload
}

// CanDecode returns a set of layers that GTP objects can decode
func (g *GTPv2) CanDecode() gopacket.LayerClass {
	return LayerTypeGTPv2
}

// NextLayerType specifies the next layer that GoPacket should attempt to
func (g *GTPv2) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
