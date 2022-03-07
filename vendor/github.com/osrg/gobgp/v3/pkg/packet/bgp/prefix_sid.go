package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
)

const (
	prefixSIDtlvHdrLen = 4
)

type TLVType uint8

type TLV struct {
	Type   TLVType
	Length uint16
}

func (s *TLV) Len() int {
	return int(s.Length) + tlvHdrLen - 1 // Extra reserved byte in the header
}

func (s *TLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length)-1 {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}
	buf := make([]byte, prefixSIDtlvHdrLen+len(value))
	p := 0
	buf[p] = byte(s.Type)
	p++
	binary.BigEndian.PutUint16(buf[p:p+2], uint16(s.Length))
	p += 2
	// Reserved byte
	p++
	copy(buf[p:], value)

	return buf, nil
}

func (s *TLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < prefixSIDtlvHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	p := 0
	s.Type = TLVType(data[p])
	p++
	s.Length = binary.BigEndian.Uint16(data[p : p+2])

	if s.Len() < prefixSIDtlvHdrLen || len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return data[prefixSIDtlvHdrLen:s.Len()], nil
}

// PrefixSIDTLVInterface defines standard set of methods to handle Prefix SID attribute's TLVs
type PrefixSIDTLVInterface interface {
	Len() int
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
}

type PrefixSIDAttribute struct {
	TLVs []PrefixSIDTLVInterface
}

type PathAttributePrefixSID struct {
	PathAttribute
	TLVs []PrefixSIDTLVInterface
}

func (p *PathAttributePrefixSID) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	tlvs, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	for len(tlvs) >= prefixSIDtlvHdrLen {
		t := &TLV{}
		_, err := t.DecodeFromBytes(tlvs)
		if err != nil {
			return err
		}

		var tlv PrefixSIDTLVInterface
		switch t.Type {
		case 5:
			tlv = &SRv6L3ServiceAttribute{
				SubTLVs: make([]PrefixSIDTLVInterface, 0),
			}
		default:
			tlvs = tlvs[t.Len():]
			continue
		}

		if err := tlv.DecodeFromBytes(tlvs); err != nil {
			return err
		}
		tlvs = tlvs[t.Len():]
		p.TLVs = append(p.TLVs, tlv)
	}

	return nil
}

func (p *PathAttributePrefixSID) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range p.TLVs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return p.PathAttribute.Serialize(buf)
}

func (p *PathAttributePrefixSID) String() string {
	var buf bytes.Buffer

	for _, tlv := range p.TLVs {
		buf.WriteString(fmt.Sprintf("%s ", tlv.String()))
	}

	return fmt.Sprintf("{Prefix SID attributes: %s}", buf.String())
}

func (p *PathAttributePrefixSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Flags BGPAttrFlag `json:"flags"`
		PrefixSIDAttribute
	}{
		p.GetType(),
		p.GetFlags(),
		*p.Extract(),
	})
}

func (p *PathAttributePrefixSID) Extract() *PrefixSIDAttribute {
	psid := &PrefixSIDAttribute{
		TLVs: make([]PrefixSIDTLVInterface, 0),
	}
	psid.TLVs = append(psid.TLVs, p.TLVs...)

	return psid
}

// SRv6L3Service defines the structure of SRv6 L3 Service object
type SRv6L3Service struct {
	SubTLVs []PrefixSIDTLVInterface
}

// SRv6L3ServiceAttribute defines the structure of SRv6 L3 Service attribute
type SRv6L3ServiceAttribute struct {
	TLV
	SubTLVs []PrefixSIDTLVInterface
}

func (s *SRv6L3ServiceAttribute) Len() int {
	return int(s.Length) + prefixSIDtlvHdrLen
}

func (s *SRv6L3ServiceAttribute) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range s.SubTLVs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}
	return s.TLV.Serialize(buf)
}

func (s *SRv6L3ServiceAttribute) DecodeFromBytes(data []byte) error {
	stlvs, err := s.TLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	for len(stlvs) >= subTLVHdrLen {
		t := &SubTLV{}
		_, err := t.DecodeFromBytes(stlvs)
		if err != nil {
			return err
		}

		var stlv PrefixSIDTLVInterface
		switch t.Type {
		case 1:
			stlv = &SRv6InformationSubTLV{
				SubSubTLVs: make([]PrefixSIDTLVInterface, 0),
			}
		default:
			data = data[t.Len():]
			continue
		}

		if err := stlv.DecodeFromBytes(stlvs); err != nil {
			return err
		}
		stlvs = stlvs[t.Len():]
		s.SubTLVs = append(s.SubTLVs, stlv)
	}

	return nil
}

func (s *SRv6L3ServiceAttribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type TLVType `json:"type"`
		SRv6L3Service
	}{
		s.Type,
		*s.Extract(),
	})
}

func (s *SRv6L3ServiceAttribute) String() string {
	var buf bytes.Buffer

	for _, tlv := range s.SubTLVs {
		buf.WriteString(fmt.Sprintf("%s ", tlv.String()))
	}

	return fmt.Sprintf("{SRv6 L3 Service Attribute: %s}", buf.String())
}

func (s *SRv6L3ServiceAttribute) Extract() *SRv6L3Service {
	l3 := &SRv6L3Service{
		SubTLVs: make([]PrefixSIDTLVInterface, 0),
	}

	l3.SubTLVs = append(l3.SubTLVs, s.SubTLVs...)

	return l3
}

const (
	subTLVHdrLen = 3
)

type SubTLVType uint8

type SubTLV struct {
	Type   SubTLVType
	Length uint16
}

func (s *SubTLV) Len() int {
	return int(s.Length) + subTLVHdrLen
}

func (s *SubTLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length) {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}
	// Extra byte is reserved
	buf := make([]byte, subTLVHdrLen+len(value))
	buf[0] = byte(s.Type)
	binary.BigEndian.PutUint16(buf[1:4], uint16(s.Length))
	// 4th reserved byte
	copy(buf[4:], value)

	return buf, nil
}

func (s *SubTLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < subTLVHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	s.Type = SubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])

	if len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return data[subTLVHdrLen:s.Len()], nil
}

type SRv6InformationSTLV struct {
	SID              []byte                  `json:"sid"`
	Flags            uint8                   `json:"flags"`
	EndpointBehavior uint16                  `json:"endpoint_behavior"`
	SubSubTLVs       []PrefixSIDTLVInterface `json:"sub_sub_tlvs,omitempty"`
}

// SRv6InformationSubTLV defines a structure of SRv6 Information Sub TLV (type 1) object
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.1
type SRv6InformationSubTLV struct {
	SubTLV
	SID              []byte
	Flags            uint8
	EndpointBehavior uint16
	SubSubTLVs       []PrefixSIDTLVInterface
}

func (s *SRv6InformationSubTLV) Len() int {
	return int(s.Length) + subTLVHdrLen
}

func (s *SRv6InformationSubTLV) Serialize() ([]byte, error) {
	buf := make([]byte, s.Length)
	p := 0
	copy(buf[p:], s.SID)
	p += len(s.SID)
	buf[p] = byte(s.Flags)
	p++
	binary.BigEndian.PutUint16(buf[p:p+2], uint16(s.EndpointBehavior))
	p += 2
	// Reserved byte
	buf[p] = 0x0
	p++
	for _, sstlv := range s.SubSubTLVs {
		sbuf, err := sstlv.Serialize()
		if err != nil {
			return nil, err
		}
		copy(buf[p:], sbuf)
		p += len(sbuf)
	}

	return s.SubTLV.Serialize(buf)
}

func (s *SRv6InformationSubTLV) DecodeFromBytes(data []byte) error {
	if len(data) < subTLVHdrLen {
		return malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	s.Type = SubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])
	// 4th reserved byte
	p := 4
	s.SID = make([]byte, 16)
	copy(s.SID, data[p:p+16])
	p += 16
	s.Flags = uint8(data[p])
	p++
	s.EndpointBehavior = binary.BigEndian.Uint16(data[p : p+2])
	p += 2
	// reserved byte
	p++
	if p+3 > len(data) {
		// There is no Sub Sub TLVs detected, returning
		return nil
	}
	stlvs := data[p:]
	for len(stlvs) >= prefixSIDtlvHdrLen {
		t := &SubSubTLV{}
		_, err := t.DecodeFromBytes(stlvs)
		if err != nil {
			return err
		}

		var sstlv PrefixSIDTLVInterface
		switch t.Type {
		case 1:
			sstlv = &SRv6SIDStructureSubSubTLV{}
		default:
			stlvs = stlvs[t.Len():]
			continue
		}

		if err := sstlv.DecodeFromBytes(stlvs); err != nil {
			return err
		}
		stlvs = stlvs[t.Len():]
		s.SubSubTLVs = append(s.SubSubTLVs, sstlv)
	}

	return nil
}

func (s *SRv6InformationSubTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type SubTLVType `json:"type"`
		SRv6InformationSTLV
	}{
		s.Type,
		*s.Extract(),
	})
}

func (s *SRv6InformationSubTLV) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("SID: %s ", net.IP(s.SID).To16().String()))
	buf.WriteString(fmt.Sprintf("Flag: %d ", s.Flags))
	buf.WriteString(fmt.Sprintf("Endpoint Behavior: %d ", s.EndpointBehavior))
	for _, tlv := range s.SubSubTLVs {
		buf.WriteString(fmt.Sprintf("%s ", tlv.String()))
	}

	return fmt.Sprintf("{SRv6 Information Sub TLV: %s}", buf.String())
}

func (s *SRv6InformationSubTLV) Extract() *SRv6InformationSTLV {
	info := &SRv6InformationSTLV{
		SID:              s.SID,
		Flags:            s.Flags,
		EndpointBehavior: s.EndpointBehavior,
		SubSubTLVs:       make([]PrefixSIDTLVInterface, 0),
	}

	info.SubSubTLVs = append(info.SubSubTLVs, s.SubSubTLVs...)

	return info
}

const (
	subSubTLVHdrLen = 3
)

type SubSubTLVType uint8

type SubSubTLV struct {
	Type   SubSubTLVType
	Length uint16
}

func (s *SubSubTLV) Len() int {
	return int(s.Length) + subSubTLVHdrLen
}

func (s *SubSubTLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length) {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}
	// Extra byte is reserved
	buf := make([]byte, subSubTLVHdrLen+len(value))
	p := 0
	buf[p] = byte(s.Type)
	p++
	binary.BigEndian.PutUint16(buf[p:p+2], uint16(s.Length))
	p += 2
	copy(buf[p:], value)

	return buf, nil
}

func (s *SubSubTLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < prefixSIDtlvHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID Sub Sub TLV malformed")
	}
	s.Type = SubSubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])

	if len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID Sub Sub TLV malformed")
	}

	return data[prefixSIDtlvHdrLen:s.Len()], nil
}

// SRv6SIDStructureSubSubTLV defines a structure of SRv6 SID Structure Sub Sub TLV (type 1) object
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SRv6SIDStructureSubSubTLV struct {
	SubSubTLV
	LocalBlockLength    uint8
	LocatorNodeLength   uint8
	FunctionLength      uint8
	ArgumentLength      uint8
	TranspositionLength uint8
	TranspositionOffset uint8
}

func (s *SRv6SIDStructureSubSubTLV) Len() int {
	return int(s.Length) + subSubTLVHdrLen
}

func (s *SRv6SIDStructureSubSubTLV) Serialize() ([]byte, error) {
	buf := make([]byte, s.Length)
	p := 0
	buf[p] = s.LocalBlockLength
	p++
	buf[p] = s.LocatorNodeLength
	p++
	buf[p] = s.FunctionLength
	p++
	buf[p] = s.ArgumentLength
	p++
	buf[p] = s.TranspositionLength
	p++
	buf[p] = s.TranspositionOffset

	return s.SubSubTLV.Serialize(buf)
}

func (s *SRv6SIDStructureSubSubTLV) DecodeFromBytes(data []byte) error {
	if len(data) < subSubTLVHdrLen {
		return malformedAttrListErr("decoding failed: Prefix SID Sub Sub TLV malformed")
	}
	s.Type = SubSubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])

	s.LocalBlockLength = data[3]
	s.LocatorNodeLength = data[4]
	s.FunctionLength = data[5]
	s.ArgumentLength = data[6]
	s.TranspositionLength = data[7]
	s.TranspositionOffset = data[8]

	return nil
}

func (s *SRv6SIDStructureSubSubTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type                SubSubTLVType `json:"type"`
		LocalBlockLength    uint8         `json:"local_block_length"`
		LocatorNodeLength   uint8         `json:"locator_node_length"`
		FunctionLength      uint8         `json:"function_length"`
		ArgumentLength      uint8         `json:"argument_length"`
		TranspositionLength uint8         `json:"transposition_length"`
		TranspositionOffset uint8         `json:"transposition_offset"`
	}{
		Type:                s.Type,
		LocalBlockLength:    s.LocalBlockLength,
		LocatorNodeLength:   s.LocatorNodeLength,
		FunctionLength:      s.FunctionLength,
		ArgumentLength:      s.ArgumentLength,
		TranspositionLength: s.TranspositionLength,
		TranspositionOffset: s.TranspositionOffset,
	})
}

func (s *SRv6SIDStructureSubSubTLV) String() string {
	return fmt.Sprintf("{SRv6 Structure Sub Sub TLV: [ Local Block Length: %d, Locator Node Length: %d, Function Length: %d, Argument Length: %d, Transposition Length: %d, Transposition Offset: %d] }",
		s.LocalBlockLength,
		s.LocatorNodeLength,
		s.FunctionLength,
		s.ArgumentLength,
		s.TranspositionLength,
		s.TranspositionOffset,
	)
}
