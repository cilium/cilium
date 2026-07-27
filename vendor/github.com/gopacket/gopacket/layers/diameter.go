package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
)

// Diameter represents a Diameter Protocol message (RFC 6733)
type Diameter struct {
	BaseLayer
	Version       uint8
	MessageLength uint32 // 24-bit field
	CommandFlags  DiameterCommandFlags
	CommandCode   uint32 // 24-bit field
	ApplicationID uint32
	HopByHopID    uint32
	EndToEndID    uint32
	AVPs          []DiameterAVP
}

// DiameterCommandFlags represents the flags in a Diameter message header
type DiameterCommandFlags struct {
	Request       bool
	Proxiable     bool
	Error         bool
	Retransmitted bool
}

// DiameterAVP represents an Attribute-Value Pair in Diameter
type DiameterAVP struct {
	Code        uint32
	Flags       DiameterAVPFlags
	Length      uint32 // 24-bit field
	VendorID    uint32 // Only present if VendorSpecific flag is set
	Data        []byte
	GroupedAVPs []DiameterAVP // For Grouped AVP types
}

// DiameterAVPFlags represents the flags in a Diameter AVP header
type DiameterAVPFlags struct {
	Vendor    bool
	Mandatory bool
	Protected bool
}

// DiameterVendor represents known Diameter vendors
type DiameterVendor uint32

// Known Diameter vendor IDs
const (
	DiameterVendorNone     DiameterVendor = 0
	DiameterVendor3GPP     DiameterVendor = 10415 // 3GPP
	DiameterVendorETSI     DiameterVendor = 13019 // ETSI
	DiameterVendorVodafone DiameterVendor = 12645 // Vodafone
	DiameterVendorCisco    DiameterVendor = 9     // Cisco
	DiameterVendorEricsson DiameterVendor = 193   // Ericsson
	DiameterVendorHuawei   DiameterVendor = 2011  // Huawei
	DiameterVendorNokia    DiameterVendor = 94    // Nokia
)

// diameterVendors maps vendor IDs to their names
var diameterVendors = map[uint32]string{
	0:     "None",
	9:     "Cisco",
	94:    "Nokia",
	193:   "Ericsson",
	2011:  "Huawei",
	10415: "3GPP",
	12645: "Vodafone",
	13019: "ETSI",
}

// GetVendorName returns the vendor name for a vendor ID
func GetVendorName(vendorID uint32) string {
	if name, ok := diameterVendors[vendorID]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", vendorID)
}

// LayerType returns gopacket.LayerTypeDiameter
func (d *Diameter) LayerType() gopacket.LayerType {
	return LayerTypeDiameter
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (d *Diameter) CanDecode() gopacket.LayerClass {
	return LayerTypeDiameter
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (d *Diameter) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns nil as Diameter is an application-layer protocol
func (d *Diameter) Payload() []byte {
	return nil
}

// decodeDiameter decodes the Diameter protocol
func decodeDiameter(data []byte, p gopacket.PacketBuilder) error {
	d := &Diameter{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	p.SetApplicationLayer(d)
	return nil
}

// DecodeFromBytes decodes the given bytes into this layer
func (d *Diameter) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return errors.New("diameter message too short, minimum 20 bytes required")
	}

	d.Version = data[0]
	if d.Version != 1 {
		return fmt.Errorf("unsupported diameter version: %d", d.Version)
	}

	// Message Length is 24 bits (bytes 1-3)
	d.MessageLength = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	if uint32(len(data)) < d.MessageLength {
		return fmt.Errorf("diameter message truncated: expected %d bytes, got %d", d.MessageLength, len(data))
	}

	// Command Flags (byte 4)
	d.CommandFlags.Request = (data[4] & 0x80) != 0
	d.CommandFlags.Proxiable = (data[4] & 0x40) != 0
	d.CommandFlags.Error = (data[4] & 0x20) != 0
	d.CommandFlags.Retransmitted = (data[4] & 0x10) != 0

	// Command Code is 24 bits (bytes 5-7)
	d.CommandCode = uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	// Application ID (bytes 8-11)
	d.ApplicationID = binary.BigEndian.Uint32(data[8:12])

	// Hop-by-Hop Identifier (bytes 12-15)
	d.HopByHopID = binary.BigEndian.Uint32(data[12:16])

	// End-to-End Identifier (bytes 16-19)
	d.EndToEndID = binary.BigEndian.Uint32(data[16:20])

	// Parse AVPs
	avpData := data[20:d.MessageLength]
	d.AVPs = []DiameterAVP{}

	for len(avpData) >= 8 {
		avp, bytesConsumed, err := decodeDiameterAVP(avpData)
		if err != nil {
			df.SetTruncated()
			break
		}
		d.AVPs = append(d.AVPs, avp)
		avpData = avpData[bytesConsumed:]
	}

	d.BaseLayer = BaseLayer{Contents: data[:d.MessageLength]}

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (d *Diameter) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Calculate total message length
	messageLength := 20 // Header size
	for _, avp := range d.AVPs {
		avpLen := SerializedAVPLength(&avp)
		messageLength += avpLen
	}

	if opts.FixLengths {
		d.MessageLength = uint32(messageLength)
	}

	bytes, err := b.PrependBytes(messageLength)
	if err != nil {
		return err
	}

	// Version
	bytes[0] = d.Version

	// Message Length (24 bits)
	bytes[1] = byte(d.MessageLength >> 16)
	bytes[2] = byte(d.MessageLength >> 8)
	bytes[3] = byte(d.MessageLength)

	// Command Flags
	bytes[4] = 0
	if d.CommandFlags.Request {
		bytes[4] |= 0x80
	}
	if d.CommandFlags.Proxiable {
		bytes[4] |= 0x40
	}
	if d.CommandFlags.Error {
		bytes[4] |= 0x20
	}
	if d.CommandFlags.Retransmitted {
		bytes[4] |= 0x10
	}

	// Command Code (24 bits)
	bytes[5] = byte(d.CommandCode >> 16)
	bytes[6] = byte(d.CommandCode >> 8)
	bytes[7] = byte(d.CommandCode)

	// Application ID
	binary.BigEndian.PutUint32(bytes[8:12], d.ApplicationID)

	// Hop-by-Hop ID
	binary.BigEndian.PutUint32(bytes[12:16], d.HopByHopID)

	// End-to-End ID
	binary.BigEndian.PutUint32(bytes[16:20], d.EndToEndID)

	// Serialize AVPs
	offset := 20
	for _, avp := range d.AVPs {
		avpBytes := SerializeDiameterAVP(&avp)
		copy(bytes[offset:], avpBytes)
		offset += len(avpBytes)
	}

	return nil
}

// GetUnsigned32 returns the AVP data as uint32
func (avp *DiameterAVP) GetUnsigned32() (uint32, error) {
	if len(avp.Data) != 4 {
		return 0, fmt.Errorf("invalid data length for Unsigned32: %d", len(avp.Data))
	}
	return binary.BigEndian.Uint32(avp.Data), nil
}

// GetUnsigned64 returns the AVP data as uint64
func (avp *DiameterAVP) GetUnsigned64() (uint64, error) {
	if len(avp.Data) != 8 {
		return 0, fmt.Errorf("invalid data length for Unsigned64: %d", len(avp.Data))
	}
	return binary.BigEndian.Uint64(avp.Data), nil
}

// GetInteger32 returns the AVP data as int32
func (avp *DiameterAVP) GetInteger32() (int32, error) {
	val, err := avp.GetUnsigned32()
	return int32(val), err
}

// GetInteger64 returns the AVP data as int64
func (avp *DiameterAVP) GetInteger64() (int64, error) {
	val, err := avp.GetUnsigned64()
	return int64(val), err
}

// GetString returns the AVP data as string
func (avp *DiameterAVP) GetString() string {
	return string(avp.Data)
}

// GetTime returns the AVP data as time.Time (NTP timestamp)
func (avp *DiameterAVP) GetTime() (time.Time, error) {
	if len(avp.Data) != 4 {
		return time.Time{}, fmt.Errorf("invalid data length for Time: %d", len(avp.Data))
	}
	// Diameter uses NTP timestamp (seconds since Jan 1, 1900)
	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	seconds := binary.BigEndian.Uint32(avp.Data)
	return ntpEpoch.Add(time.Duration(seconds) * time.Second), nil
}

// IsRequest returns true if this is a request message
func (d *Diameter) IsRequest() bool {
	return d.CommandFlags.Request
}

// IsProxiable returns true if the message may be proxied
func (d *Diameter) IsProxiable() bool {
	return d.CommandFlags.Proxiable
}

// IsError returns true if this is an error message
func (d *Diameter) IsError() bool {
	return d.CommandFlags.Error
}

// IsRetransmitted returns true if this is a retransmitted message
func (d *Diameter) IsRetransmitted() bool {
	return d.CommandFlags.Retransmitted
}

// IsMandatory returns true if the AVP is mandatory
func (avp *DiameterAVP) IsMandatory() bool {
	return avp.Flags.Mandatory
}

// IsVendorSpecific returns true if the AVP is vendor-specific
func (avp *DiameterAVP) IsVendorSpecific() bool {
	return avp.Flags.Vendor
}

// IsProtected returns true if the AVP is protected
func (avp *DiameterAVP) IsProtected() bool {
	return avp.Flags.Protected
}

// GetAVPTypeName returns the type name for this AVP
func (avp *DiameterAVP) GetAVPTypeName() string {
	avpType, known := GetDiameterAVPType(avp.Code, avp.VendorID)
	typeStr := "Unknown"
	if known {
		switch avpType {
		case DiameterAVPTypeOctetString:
			typeStr = "OctetString"
		case DiameterAVPTypeInteger32:
			typeStr = "Integer32"
		case DiameterAVPTypeInteger64:
			typeStr = "Integer64"
		case DiameterAVPTypeUnsigned32:
			typeStr = "Unsigned32"
		case DiameterAVPTypeUnsigned64:
			typeStr = "Unsigned64"
		case DiameterAVPTypeFloat32:
			typeStr = "Float32"
		case DiameterAVPTypeFloat64:
			typeStr = "Float64"
		case DiameterAVPTypeGrouped:
			typeStr = "Grouped"
		case DiameterAVPTypeAddress:
			typeStr = "Address"
		case DiameterAVPTypeTime:
			typeStr = "Time"
		case DiameterAVPTypeUTF8String:
			typeStr = "UTF8String"
		case DiameterAVPTypeDiameterIdentity:
			typeStr = "DiameterIdentity"
		case DiameterAVPTypeDiameterURI:
			typeStr = "DiameterURI"
		case DiameterAVPTypeEnumerated:
			typeStr = "Enumerated"
		case DiameterAVPTypeIPFilterRule:
			typeStr = "IPFilterRule"
		}
	}
	return typeStr
}

// String returns a string representation of the AVP
func (avp *DiameterAVP) String() string {
	flags := ""
	if avp.Flags.Vendor {
		flags += "V"
	}
	if avp.Flags.Mandatory {
		flags += "M"
	}
	if avp.Flags.Protected {
		flags += "P"
	}
	if flags == "" {
		flags = "-"
	}

	vendorInfo := ""
	if avp.Flags.Vendor {
		vendorInfo = fmt.Sprintf(" Vendor=%s(%d)", GetVendorName(avp.VendorID), avp.VendorID)
	}

	groupedInfo := ""
	if len(avp.GroupedAVPs) > 0 {
		groupedInfo = fmt.Sprintf(" [%d sub-AVPs]", len(avp.GroupedAVPs))
	}

	return fmt.Sprintf("AVP{Code=%d, Flags=%s, Type=%s, Length=%d%s%s}",
		avp.Code, flags, avp.GetAVPTypeName(), avp.Length, vendorInfo, groupedInfo)
}

// GetVendorIDFromAVP is a convenience method to get vendor name from AVP
func (avp *DiameterAVP) GetVendorIDString() string {
	if avp.Flags.Vendor {
		return GetVendorName(avp.VendorID)
	}
	return "None"
}
