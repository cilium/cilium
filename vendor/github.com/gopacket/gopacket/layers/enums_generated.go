// Copyright 2012 Google, Inc. All rights reserved.

package layers

// Created by gen2.go, don't edit manually
// Generated at 2023-09-26 15:45:59.728838421 +0400 +04 m=+0.000090902

import (
	"fmt"

	"github.com/gopacket/gopacket"
)

func init() {
	initActualTypeData()
}

// Decoder calls LinkTypeMetadata.DecodeWith's decoder.
func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 277 {
		if metadata := LinkTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode LinkType %d", a)
}

// String returns LinkTypeMetadata.Name.
func (a LinkType) String() string {
	if int(a) < 277 {
		if metadata := LinkTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownLinkType"
}

// LayerType returns LinkTypeMetadata.LayerType.
func (a LinkType) LayerType() gopacket.LayerType {
	if int(a) < 277 {
		if metadata := LinkTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var LinkTypeMetadata [277]EnumMetadata

// Decoder calls EthernetTypeMetadata.DecodeWith's decoder.
func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 65536 {
		if metadata := EthernetTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode EthernetType %d", a)
}

// String returns EthernetTypeMetadata.Name.
func (a EthernetType) String() string {
	if int(a) < 65536 {
		if metadata := EthernetTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownEthernetType"
}

// LayerType returns EthernetTypeMetadata.LayerType.
func (a EthernetType) LayerType() gopacket.LayerType {
	if int(a) < 65536 {
		if metadata := EthernetTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var EthernetTypeMetadata [65536]EnumMetadata

// Decoder calls PPPTypeMetadata.DecodeWith's decoder.
func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 65536 {
		if metadata := PPPTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode PPPType %d", a)
}

// String returns PPPTypeMetadata.Name.
func (a PPPType) String() string {
	if int(a) < 65536 {
		if metadata := PPPTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownPPPType"
}

// LayerType returns PPPTypeMetadata.LayerType.
func (a PPPType) LayerType() gopacket.LayerType {
	if int(a) < 65536 {
		if metadata := PPPTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var PPPTypeMetadata [65536]EnumMetadata

// Decoder calls IPProtocolMetadata.DecodeWith's decoder.
func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := IPProtocolMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode IPProtocol %d", a)
}

// String returns IPProtocolMetadata.Name.
func (a IPProtocol) String() string {
	if int(a) < 256 {
		if metadata := IPProtocolMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownIPProtocol"
}

// LayerType returns IPProtocolMetadata.LayerType.
func (a IPProtocol) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := IPProtocolMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var IPProtocolMetadata [256]EnumMetadata

// Decoder calls SCTPChunkTypeMetadata.DecodeWith's decoder.
func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := SCTPChunkTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode SCTPChunkType %d", a)
}

// String returns SCTPChunkTypeMetadata.Name.
func (a SCTPChunkType) String() string {
	if int(a) < 256 {
		if metadata := SCTPChunkTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownSCTPChunkType"
}

// LayerType returns SCTPChunkTypeMetadata.LayerType.
func (a SCTPChunkType) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := SCTPChunkTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var SCTPChunkTypeMetadata [256]EnumMetadata

// Decoder calls PPPoECodeMetadata.DecodeWith's decoder.
func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := PPPoECodeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode PPPoECode %d", a)
}

// String returns PPPoECodeMetadata.Name.
func (a PPPoECode) String() string {
	if int(a) < 256 {
		if metadata := PPPoECodeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownPPPoECode"
}

// LayerType returns PPPoECodeMetadata.LayerType.
func (a PPPoECode) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := PPPoECodeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var PPPoECodeMetadata [256]EnumMetadata

// Decoder calls FDDIFrameControlMetadata.DecodeWith's decoder.
func (a FDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := FDDIFrameControlMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode FDDIFrameControl %d", a)
}

// String returns FDDIFrameControlMetadata.Name.
func (a FDDIFrameControl) String() string {
	if int(a) < 256 {
		if metadata := FDDIFrameControlMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownFDDIFrameControl"
}

// LayerType returns FDDIFrameControlMetadata.LayerType.
func (a FDDIFrameControl) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := FDDIFrameControlMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var FDDIFrameControlMetadata [256]EnumMetadata

// Decoder calls EAPOLTypeMetadata.DecodeWith's decoder.
func (a EAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := EAPOLTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode EAPOLType %d", a)
}

// String returns EAPOLTypeMetadata.Name.
func (a EAPOLType) String() string {
	if int(a) < 256 {
		if metadata := EAPOLTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownEAPOLType"
}

// LayerType returns EAPOLTypeMetadata.LayerType.
func (a EAPOLType) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := EAPOLTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var EAPOLTypeMetadata [256]EnumMetadata

// Decoder calls ProtocolFamilyMetadata.DecodeWith's decoder.
func (a ProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := ProtocolFamilyMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode ProtocolFamily %d", a)
}

// String returns ProtocolFamilyMetadata.Name.
func (a ProtocolFamily) String() string {
	if int(a) < 256 {
		if metadata := ProtocolFamilyMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownProtocolFamily"
}

// LayerType returns ProtocolFamilyMetadata.LayerType.
func (a ProtocolFamily) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := ProtocolFamilyMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var ProtocolFamilyMetadata [256]EnumMetadata

// Decoder calls Dot11TypeMetadata.DecodeWith's decoder.
func (a Dot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := Dot11TypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode Dot11Type %d", a)
}

// String returns Dot11TypeMetadata.Name.
func (a Dot11Type) String() string {
	if int(a) < 256 {
		if metadata := Dot11TypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownDot11Type"
}

// LayerType returns Dot11TypeMetadata.LayerType.
func (a Dot11Type) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := Dot11TypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var Dot11TypeMetadata [256]EnumMetadata

// Decoder calls USBTransportTypeMetadata.DecodeWith's decoder.
func (a USBTransportType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) < 256 {
		if metadata := USBTransportTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.DecodeWith.Decode(data, p)
		}
	}

	return fmt.Errorf("Unable to decode USBTransportType %d", a)
}

// String returns USBTransportTypeMetadata.Name.
func (a USBTransportType) String() string {
	if int(a) < 256 {
		if metadata := USBTransportTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.Name
		}
	}

	return "UnknownUSBTransportType"
}

// LayerType returns USBTransportTypeMetadata.LayerType.
func (a USBTransportType) LayerType() gopacket.LayerType {
	if int(a) < 256 {
		if metadata := USBTransportTypeMetadata[a]; metadata.DecodeWith != nil {
			return metadata.LayerType
		}
	}

	return 0
}

var USBTransportTypeMetadata [256]EnumMetadata
