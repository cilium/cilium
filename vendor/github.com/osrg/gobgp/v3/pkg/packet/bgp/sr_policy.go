package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

type SRPolicyNLRI struct {
	PrefixDefault
	rf            RouteFamily
	Length        uint8
	Distinguisher uint32
	Color         uint32
	Endpoint      []byte
}

const (
	// SRPolicyIPv4NLRILen defines IPv4 SR Policy NLRI portion length in bits
	SRPolicyIPv4NLRILen = 96
	// SRPolicyIPv6NLRILen defines IPv6 SR Policy NLRI portion length in bits
	SRPolicyIPv6NLRILen = 192
)

func (s *SRPolicyNLRI) Flat() map[string]string {
	return map[string]string{}
}

func (s *SRPolicyNLRI) decodeFromBytes(rf RouteFamily, data []byte, options ...*MarshallingOption) error {
	if IsAddPathEnabled(true, rf, options) {
		var err error
		data, err = s.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	switch data[0] {
	case SRPolicyIPv4NLRILen:
		s.rf = RF_SR_POLICY_IPv4
	case SRPolicyIPv6NLRILen:
		s.rf = RF_SR_POLICY_IPv6
	default:
		msg := fmt.Sprintf("Invalid length %d for SR Policy NLRI", len(data))
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
	}
	p := 0
	s.Length = data[p] / 8
	p++
	s.Distinguisher = binary.BigEndian.Uint32(data[p : p+4])
	p += 4
	s.Color = binary.BigEndian.Uint32(data[p : p+4])
	p += 4
	s.Endpoint = data[p:]

	return nil
}

func (s *SRPolicyNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 1+s.Length)
	p := 0
	buf[0] = s.Length * 8
	p++
	binary.BigEndian.PutUint32(buf[p:p+4], s.Distinguisher)
	p += 4
	binary.BigEndian.PutUint32(buf[p:p+4], s.Color)
	p += 4
	copy(buf[p:], s.Endpoint)
	if IsAddPathEnabled(false, s.rf, options) {
		id, err := s.serializeIdentifier()
		if err != nil {
			return nil, err
		}
		return append(id, buf...), nil
	}
	return buf, nil
}

func (s *SRPolicyNLRI) AFI() uint16 {
	afi, _ := RouteFamilyToAfiSafi(s.rf)
	return afi
}

func (s *SRPolicyNLRI) SAFI() uint8 {
	_, safi := RouteFamilyToAfiSafi(s.rf)
	return safi
}

func (s *SRPolicyNLRI) Len(options ...*MarshallingOption) int {
	buf, _ := s.Serialize(options...)
	return len(buf)
}

func (s *SRPolicyNLRI) String() string {
	afi, _ := RouteFamilyToAfiSafi(s.rf)
	var endp string
	switch afi {
	case AFI_IP:
		endp = net.IP(s.Endpoint).To4().String()
	case AFI_IP6:
		endp = net.IP(s.Endpoint).To16().String()
	default:
		endp = "[" + string(s.Endpoint) + "]"
	}
	return fmt.Sprintf("{ Length: %d (bytes), Distinguisher: %d, Color %d, Endpoint: %s }", s.Length, s.Distinguisher, s.Color, endp)
}

func (s *SRPolicyNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Length        uint8  `json:"length"`
		Distinguisher uint32 `json:"distinguisher"`
		Color         uint32 `json:"color"`
		Endpoint      string `json:"endpoint"`
	}{
		Length:        s.Length,
		Distinguisher: s.Distinguisher,
		Color:         s.Color,
		Endpoint:      string(s.Endpoint),
	})
}

type SRPolicyIPv4 struct {
	SRPolicyNLRI
}

func (s *SRPolicyIPv4) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return s.decodeFromBytes(s.rf, data)
}

func NewSRPolicyIPv4(l uint32, d uint32, c uint32, ep []byte) *SRPolicyIPv4 {
	return &SRPolicyIPv4{
		SRPolicyNLRI: SRPolicyNLRI{
			rf:            RF_SR_POLICY_IPv4,
			Length:        uint8(l / 8),
			Distinguisher: d,
			Color:         c,
			Endpoint:      ep,
		},
	}
}

type SRPolicyIPv6 struct {
	SRPolicyNLRI
}

func (s *SRPolicyIPv6) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return s.decodeFromBytes(s.rf, data)
}

func NewSRPolicyIPv6(l uint32, d uint32, c uint32, ep []byte) *SRPolicyIPv6 {
	return &SRPolicyIPv6{
		SRPolicyNLRI: SRPolicyNLRI{
			rf:            RF_SR_POLICY_IPv6,
			Length:        uint8(l / 8),
			Distinguisher: d,
			Color:         c,
			Endpoint:      ep,
		},
	}
}

type TunnelEncapSubTLVSRPreference struct {
	TunnelEncapSubTLV
	Flags      uint8
	Preference uint32
}

func (t *TunnelEncapSubTLVSRPreference) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	// Second byte carries the length of SR Preference SubTLV
	if t.Length != 6 {
		msg := fmt.Sprintf("Invalid TunnelEncapSubTLVSRPreference length: %d", t.Length)
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
	}
	t.Flags = value[0]
	t.Preference = binary.BigEndian.Uint32(value[2:6])
	return nil
}

func (t *TunnelEncapSubTLVSRPreference) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = t.Flags
	binary.BigEndian.PutUint32(buf[2:6], t.Preference)
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRPreference) String() string {
	return fmt.Sprintf("{Flags: 0x%02x, Preference: %d}", t.Flags, t.Preference)
}

func (t *TunnelEncapSubTLVSRPreference) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type       EncapSubTLVType `json:"type"`
		Flags      uint8           `json:"flags"`
		Preference uint32          `json:"preference"`
	}{
		Type:       t.Type,
		Flags:      t.Flags,
		Preference: t.Preference,
	})
}

func NewTunnelEncapSubTLVSRPreference(flags uint32, preference uint32) *TunnelEncapSubTLVSRPreference {
	return &TunnelEncapSubTLVSRPreference{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type:   ENCAP_SUBTLV_TYPE_SRPREFERENCE,
			Length: 6,
		},
		Flags:      uint8(flags),
		Preference: preference,
	}
}

type TunnelEncapSubTLVSRPriority struct {
	TunnelEncapSubTLV
	Priority uint8
}

func (t *TunnelEncapSubTLVSRPriority) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	// Second byte carries the length of SR Preference SubTLV
	if t.Length != 2 {
		msg := fmt.Sprintf("Invalid TunnelEncapSubTLVSRPriority length: %d", t.Length)
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
	}
	t.Priority = value[0]
	return nil
}

func (t *TunnelEncapSubTLVSRPriority) Serialize() ([]byte, error) {
	buf := make([]byte, 1+1)
	buf[0] = t.Priority
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRPriority) String() string {
	return fmt.Sprintf("{Priority: %d}", t.Priority)
}

func (t *TunnelEncapSubTLVSRPriority) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     EncapSubTLVType `json:"type"`
		Priority uint8           `json:"priority"`
	}{
		Type:     t.Type,
		Priority: t.Priority,
	})
}

func NewTunnelEncapSubTLVSRPriority(priority uint8) *TunnelEncapSubTLVSRPriority {
	return &TunnelEncapSubTLVSRPriority{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type:   ENCAP_SUBTLV_TYPE_SRPRIORITY,
			Length: 2,
		},
		Priority: priority,
	}
}

type TunnelEncapSubTLVSRCandidatePathName struct {
	TunnelEncapSubTLV
	CandidatePathName string
}

func (t *TunnelEncapSubTLVSRCandidatePathName) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	// Skip Reserved byte
	t.CandidatePathName = string(value[1:t.TunnelEncapSubTLV.Len()])
	return nil
}

func (t *TunnelEncapSubTLVSRCandidatePathName) Serialize() ([]byte, error) {
	buf := make([]byte, 1+len(t.CandidatePathName))
	copy(buf[1:], t.CandidatePathName)
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRCandidatePathName) String() string {
	return fmt.Sprintf("{Candidate Path Name: %s}", t.CandidatePathName)
}

func (t *TunnelEncapSubTLVSRCandidatePathName) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type              EncapSubTLVType `json:"type"`
		CandidatePathName string          `json:"candidate_path_name"`
	}{
		Type:              t.Type,
		CandidatePathName: t.CandidatePathName,
	})
}

func NewTunnelEncapSubTLVSRCandidatePathName(cpn string) *TunnelEncapSubTLVSRCandidatePathName {
	return &TunnelEncapSubTLVSRCandidatePathName{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type:   ENCAP_SUBTLV_TYPE_SRCANDIDATE_PATH_NAME,
			Length: uint16(len(cpn) + 1), // length of Candidate Path name string + 1 Reserved byte
		},
		CandidatePathName: cpn,
	}
}

type SRENLPValue uint8

const (
	// ENLPType1 Indicates to push an IPv4 Explicit NULL label on an unlabeled IPv4
	// packet, but do not push an IPv6 Explicit NULL label on an
	// unlabeled IPv6 packet.
	ENLPType1 SRENLPValue = 1
	// ENLPType2 Indicates to push an IPv6 Explicit NULL label on an unlabeled IPv6
	// packet, but do not push an IPv4 Explicit NULL label on an
	// unlabeled IPv4 packet.
	ENLPType2 SRENLPValue = 2
	// ENLPType3 Indicates to push an IPv4 Explicit NULL label on an unlabeled IPv4
	// packet, and push an IPv6 Explicit NULL label on an unlabeled
	// IPv6 packet.
	ENLPType3 SRENLPValue = 3
	// ENLPType4 Indicates to not push an Explicit NULL label.
	ENLPType4 SRENLPValue = 4
)

type TunnelEncapSubTLVSRENLP struct {
	TunnelEncapSubTLV
	Flags uint8
	ENLP  SRENLPValue
}

func (t *TunnelEncapSubTLVSRENLP) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	// Second byte carries the length of SR Preference SubTLV
	if t.Length != 3 {
		msg := fmt.Sprintf("Invalid TunnelEncapSubTLVSRENLP length: %d", t.Length)
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
	}
	t.Flags = value[0]
	switch SRENLPValue(value[2]) {
	case ENLPType1:
	case ENLPType2:
	case ENLPType3:
	case ENLPType4:
	default:
		msg := fmt.Sprintf("Invalid ENLP Type: %d", value[2])
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
	}
	t.ENLP = SRENLPValue(value[2])
	return nil
}

func (t *TunnelEncapSubTLVSRENLP) Serialize() ([]byte, error) {
	buf := make([]byte, t.Length)
	buf[0] = t.Flags
	buf[2] = byte(t.ENLP)
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRENLP) String() string {
	return fmt.Sprintf("{Flags: 0x%02x, ENLP Type: %d}", t.Flags, t.ENLP)
}

func (t *TunnelEncapSubTLVSRENLP) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  EncapSubTLVType `json:"type"`
		Flags uint8           `json:"flags"`
		ENLP  uint8           `json:"enlp"`
	}{
		Type:  t.Type,
		Flags: t.Flags,
		ENLP:  uint8(t.ENLP),
	})
}

func NewTunnelEncapSubTLVSRENLP(flags uint32, enlp SRENLPValue) *TunnelEncapSubTLVSRENLP {
	return &TunnelEncapSubTLVSRENLP{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type:   ENCAP_SUBTLV_TYPE_SRENLP,
			Length: 3,
		},
		Flags: uint8(flags),
		ENLP:  enlp,
	}
}

type BSID struct {
	Value []byte
}

func (b *BSID) String() string {
	switch len(b.Value) {
	case 0:
		return "n/a"
	case 4:
		bsid := binary.BigEndian.Uint32(b.Value)
		bsid >>= 12
		return strconv.Itoa(int(bsid))
	case 16:
		return net.IP(b.Value).To16().String()
	default:
		return "invalid"
	}
}

func (b *BSID) Serialize() []byte {
	return b.Value
}
func (b *BSID) Len() int {
	return len(b.Value)
}

func NewBSID(v []byte) (*BSID, error) {
	var bsid *BSID
	switch len(v) {
	case 0:
	case 4:
		t := binary.BigEndian.Uint32(v)
		t <<= 12
		bsid = &BSID{
			Value: make([]byte, len(v)),
		}
		binary.BigEndian.PutUint32(bsid.Value, t)
	case 16:
		bsid = &BSID{
			Value: make([]byte, len(v)),
		}
		copy(bsid.Value, v)
	default:
		return nil, fmt.Errorf("invalid length %d", len(v))
	}

	return bsid, nil
}

type TunnelEncapSubTLVSRBSID struct {
	TunnelEncapSubTLV
	Flags uint8
	BSID  *BSID
}

func (t *TunnelEncapSubTLVSRBSID) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	// Check Sub TLV length, only 3 possible length are allowed
	switch t.Length {
	case 2: // No BSID, do not initializing BSID struct
	case 6:
		fallthrough
	case 18:
		t.BSID = &BSID{
			Value: make([]byte, t.Length-2),
		}
		copy(t.BSID.Value, value[2:t.Length])
	default:
		msg := fmt.Sprintf("Invalid TunnelEncapSubTLVSRBSID length: %d", t.Length)
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
	}
	t.Flags = value[0]
	return nil
}

func (t *TunnelEncapSubTLVSRBSID) Serialize() ([]byte, error) {
	l := 2
	if t.BSID != nil {
		l += t.BSID.Len()
	}
	buf := make([]byte, l) // 1st byte Flags, 2nd byte Reserved, 3rd+ BSID
	buf[0] = t.Flags
	if t.BSID != nil {
		bsid := t.BSID.Serialize()
		copy(buf[2:], bsid)
	}
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRBSID) String() string {
	return fmt.Sprintf("{S-Flag: %t, I-Flag: %t, BSID: %s}", t.Flags&0x80 == 0x80, t.Flags&0x40 == 0x40, t.BSID.String())
}

func (t *TunnelEncapSubTLVSRBSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  EncapSubTLVType `json:"type"`
		Flags uint8           `json:"flags"`
		BSID  string          `json:"binding_sid,omitempty"`
	}{
		Type:  t.Type,
		Flags: t.Flags,
		BSID:  t.BSID.String(),
	})
}

type TunnelEncapSubTLVSRv6BSID struct {
	TunnelEncapSubTLV
	Flags uint8
	BSID  *BSID
	EPBAS *SRv6EndpointBehaviorStructure
}

func (t *TunnelEncapSubTLVSRv6BSID) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	t.Flags = value[0]
	t.BSID, err = NewBSID(value[2:t.Length])
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	return nil
}

func (t *TunnelEncapSubTLVSRv6BSID) Serialize() ([]byte, error) {
	buf := make([]byte, t.Length)
	buf[0] = t.Flags
	copy(buf[2:t.BSID.Len()], t.BSID.Serialize())
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRv6BSID) String() string {
	return fmt.Sprintf("{S-Flag: %t, I-Flag: %t, B-Flag: %t, BSID: %s}", t.Flags&0x80 == 0x80, t.Flags&0x40 == 0x40, t.Flags&0x20 == 0x20, t.BSID.String())
}

func (t *TunnelEncapSubTLVSRv6BSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  EncapSubTLVType `json:"type"`
		Flags uint8           `json:"flags"`
		BSID  string          `json:"binding_sid,omitempty"`
	}{
		Type:  t.Type,
		Flags: t.Flags,
		BSID:  t.BSID.String(),
	})
}

// SegmentType defines a type of Segment in Segment List
type SegmentType int

const (
	// TypeA Segment Sub-TLV encodes a single SR-MPLS SID
	TypeA SegmentType = 1
	// TypeB Segment Sub-TLV encodes a single SRv6 SID.
	TypeB SegmentType = 13
	// TypeC Segment Sub-TLV encodes an IPv4 node address, SR Algorithm
	// and an optional SR-MPLS SID
	TypeC SegmentType = 3
	// TypeD Segment Sub-TLV encodes an IPv6 node address, SR Algorithm
	// and an optional SR-MPLS SID.
	TypeD SegmentType = 4
	// TypeE Segment Sub-TLV encodes an IPv4 node address, a local
	// interface Identifier (Local Interface ID) and an optional SR-MPLS
	// SID.
	TypeE SegmentType = 5
	// TypeF Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SR-MPLS SID.
	TypeF SegmentType = 6
	// TypeG Segment Sub-TLV encodes an IPv6 Link Local adjacency with
	// IPv6 local node address, a local interface identifier (Local
	// Interface ID), IPv6 remote node address , a remote interface
	// identifier (Remote Interface ID) and an optional SR-MPLS SID.
	TypeG SegmentType = 7
	// TypeH Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SR-MPLS SID.
	TypeH SegmentType = 8
	// TypeI Segment Sub-TLV encodes an IPv6 node address, SR Algorithm
	// and an optional SRv6 SID.
	TypeI SegmentType = 14
	// TypeJ Segment Sub-TLV encodes an IPv6 Link Local adjacency with
	// local node address, a local interface identifier (Local Interface
	// ID), remote IPv6 node address, a remote interface identifier (Remote
	// Interface ID) and an optional SRv6 SID.
	TypeJ SegmentType = 15
	// TypeK Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SRv6 SID.
	TypeK SegmentType = 16
)

// Weight sub-TLV specifies the weight associated to a given segment list.
type SegmentListWeight struct {
	TunnelEncapSubTLV
	Flags  uint8
	Weight uint32
}

func (s *SegmentListWeight) DecodeFromBytes(data []byte) error {
	value, err := s.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	s.Flags = value[0]
	s.Weight = binary.BigEndian.Uint32(value[2:6])
	return nil
}
func (s *SegmentListWeight) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = s.Flags
	binary.BigEndian.PutUint32(buf[2:6], s.Weight)
	return s.TunnelEncapSubTLV.Serialize(buf)
}
func (s *SegmentListWeight) String() string {
	return fmt.Sprintf("{Flags: 0x%02x, Weight: %d}", s.Flags, s.Weight)
}

func (s *SegmentListWeight) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   EncapSubTLVType `json:"type"`
		Flags  uint8           `json:"flags"`
		Weight uint32          `json:"weight,omitempty"`
	}{
		Type:   s.Type,
		Flags:  s.Flags,
		Weight: s.Weight,
	})
}

type SegmentTypeA struct {
	TunnelEncapSubTLV
	Flags uint8
	Label uint32
}

func (s *SegmentTypeA) DecodeFromBytes(data []byte) error {
	value, err := s.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	s.Flags = value[0]
	s.Label = binary.BigEndian.Uint32(value[2:6])
	return nil
}
func (s *SegmentTypeA) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = s.Flags
	binary.BigEndian.PutUint32(buf[2:6], s.Label)
	return s.TunnelEncapSubTLV.Serialize(buf)
}
func (s *SegmentTypeA) String() string {
	return fmt.Sprintf("{V-flag: %t, A-flag:, %t S-flag: %t, B-flag: %t, Label: %d TC: %d S: %t TTL: %d}",
		s.Flags&0x80 == 0x80, s.Flags&0x40 == 0x40, s.Flags&0x20 == 0x20, s.Flags&0x10 == 0x10,
		s.Label>>12, s.Label&0x00000e00>>9, s.Label&0x00000100 == 0x00000100, s.Label&0x000000ff)
}

func (s *SegmentTypeA) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  EncapSubTLVType `json:"type"`
		VFlag bool            `json:"v_flag"`
		AFlag bool            `json:"a_flag"`
		SFlag bool            `json:"s_flag"`
		BFlag bool            `json:"b_flag"`
		Label uint32          `json:"label"`
		TC    uint8           `json:"tc"`
		S     bool            `json:"s"`
		TTL   uint8           `json:"ttl"`
	}{
		Type:  s.Type,
		VFlag: s.Flags&0x80 == 0x80,
		AFlag: s.Flags&0x40 == 0x40,
		SFlag: s.Flags&0x20 == 0x20,
		BFlag: s.Flags&0x10 == 0x10,
		Label: s.Label >> 12,
		TC:    uint8(s.Label & 0x00000e00 >> 9),
		S:     s.Label&0x00000100 == 0x00000100,
		TTL:   uint8(s.Label & 0x000000ff),
	})
}

//go:generate go run internal/generate.go SRBehavior
//go:generate stringer -type=SRBehavior
type SRBehavior int32

type SRv6EndpointBehaviorStructure struct {
	Behavior SRBehavior
	BlockLen uint8
	NodeLen  uint8
	FuncLen  uint8
	ArgLen   uint8
}

func (s *SRv6EndpointBehaviorStructure) DecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Malformed BGP message")
	}
	behavior := binary.BigEndian.Uint16(data[0:2])
	s.Behavior = SRBehavior(behavior)
	s.BlockLen = data[4]
	s.NodeLen = data[5]
	s.FuncLen = data[6]
	s.ArgLen = data[7]
	return nil
}

func (s *SRv6EndpointBehaviorStructure) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(s.Behavior))
	buf[4] = s.BlockLen
	buf[5] = s.NodeLen
	buf[6] = s.FuncLen
	buf[7] = s.ArgLen
	return buf, nil
}

func (s *SRv6EndpointBehaviorStructure) String() string {
	return fmt.Sprintf("{Behavior: %s, BlockLen: %d, NodeLen: %d, FuncLen: %d, ArgLen: %d}",
		s.Behavior.String(), s.BlockLen, s.NodeLen, s.FuncLen, s.ArgLen)
}

func (s *SRv6EndpointBehaviorStructure) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Behavior SRBehavior `json:"behavior"`
		BlockLen uint8      `json:"block_Len"`
		NodeLen  uint8      `json:"node_len"`
		FuncLen  uint8      `json:"func_len"`
		ArgLen   uint8      `json:"arg_len"`
	}{
		Behavior: s.Behavior,
		BlockLen: s.BlockLen,
		NodeLen:  s.NodeLen,
		FuncLen:  s.FuncLen,
		ArgLen:   s.ArgLen,
	})
}

type SegmentTypeB struct {
	TunnelEncapSubTLV
	Flags   uint8
	SID     []byte
	SRv6EBS *SRv6EndpointBehaviorStructure
}

func (s *SegmentTypeB) DecodeFromBytes(data []byte) error {
	value, err := s.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	if len(value) < 18 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Malformed BGP message")
	}
	s.Flags = value[0]
	s.SID = value[2:18]

	if len(value) == 26 {
		s.SRv6EBS = &SRv6EndpointBehaviorStructure{}
		err = s.SRv6EBS.DecodeFromBytes(value[18:])
		if err != nil {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
		}
	}
	return nil
}
func (s *SegmentTypeB) Serialize() ([]byte, error) {
	buf := make([]byte, 18)
	buf[0] = s.Flags
	copy(buf[2:], s.SID)
	if s.SRv6EBS != nil {
		if ebs, _ := s.SRv6EBS.Serialize(); ebs != nil {
			buf = append(buf, ebs...)
		}
	}

	return s.TunnelEncapSubTLV.Serialize(buf)
}
func (s *SegmentTypeB) String() string {
	if s.SRv6EBS == nil {
		return fmt.Sprintf("{V-flag: %t, A-flag:, %t S-flag: %t, B-flag: %t, Sid: %s}",
			s.Flags&0x80 == 0x80, s.Flags&0x40 == 0x40, s.Flags&0x20 == 0x20, s.Flags&0x10 == 0x10, net.IP(s.SID).To16().String())
	} else {
		return fmt.Sprintf("{V-flag: %t, A-flag:, %t S-flag: %t, B-flag: %t, Sid: %s, Ebs: %s}",
			s.Flags&0x80 == 0x80, s.Flags&0x40 == 0x40, s.Flags&0x20 == 0x20, s.Flags&0x10 == 0x10, net.IP(s.SID).To16().String(),
			s.SRv6EBS.String())
	}

}

func (s *SegmentTypeB) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    EncapSubTLVType                `json:"type"`
		VFlag   bool                           `json:"v_flag"`
		AFlag   bool                           `json:"a_flag"`
		SFlag   bool                           `json:"s_flag"`
		BFlag   bool                           `json:"b_flag"`
		Sid     string                         `json:"sid"`
		SRv6EBS *SRv6EndpointBehaviorStructure `json:"endpointBehaviorStructure"`
	}{
		Type:    s.Type,
		VFlag:   s.Flags&0x80 == 0x80,
		AFlag:   s.Flags&0x40 == 0x40,
		SFlag:   s.Flags&0x20 == 0x20,
		BFlag:   s.Flags&0x10 == 0x10,
		Sid:     net.IP(s.SID).To16().String(),
		SRv6EBS: s.SRv6EBS,
	})
}

const (
	// SegmentListSubTLVWeight defines code for Segment List's Weight sub-TLV
	SegmentListSubTLVWeight = 9
)

type TunnelEncapSubTLVSRSegmentList struct {
	TunnelEncapSubTLV
	Weight   *SegmentListWeight
	Segments []TunnelEncapSubTLVInterface
}

func (t *TunnelEncapSubTLVSRSegmentList) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
	}
	if len(value) < 1 {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Malformed BGP message")
	}
	// Skip reserved byte to access inner SubTLV type
	value = value[1:]
	var segments []TunnelEncapSubTLVInterface
	p := 0
	for p < t.TunnelEncapSubTLV.Len()-4 {
		var segment TunnelEncapSubTLVInterface
		switch SegmentType(value[0]) {
		case SegmentListSubTLVWeight:
			t.Weight = &SegmentListWeight{}
			if err := t.Weight.DecodeFromBytes(value); err != nil {
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
			}
			p += t.Weight.TunnelEncapSubTLV.Len()
			value = value[t.Weight.TunnelEncapSubTLV.Len():]
			continue
		case TypeA:
			segment = &SegmentTypeA{}
			if err := segment.DecodeFromBytes(value); err != nil {
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
			}
		case TypeB:
			segment = &SegmentTypeB{}
			if err := segment.DecodeFromBytes(value); err != nil {
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, err.Error())
			}
		case TypeC:
			fallthrough
		case TypeD:
			fallthrough
		case TypeE:
			fallthrough
		case TypeF:
			fallthrough
		case TypeG:
			fallthrough
		case TypeH:
			fallthrough
		case TypeI:
			fallthrough
		case TypeJ:
			fallthrough
		case TypeK:
			msg := fmt.Sprintf("Invalid SR Policy Segment SubTLV %d is not yet supported", value[0])
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
		default:
			msg := fmt.Sprintf("Invalid SR Policy Segment List SubTLV %d", value[0])
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, msg)
		}
		segments = append(segments, segment)
		p += segment.Len()
		value = value[segment.Len():]
	}
	if len(segments) == 0 {
		t.Segments = nil
	} else {
		t.Segments = segments
	}
	return nil
}

func (t *TunnelEncapSubTLVSRSegmentList) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	// Add reserved byte
	buf = append(buf, 0x0)
	if t.Weight != nil {
		wbuf, err := t.Weight.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, wbuf...)
	}
	for _, s := range t.Segments {
		sbuf, err := s.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, sbuf...)
	}
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVSRSegmentList) String() string {
	msg := "{"
	if t.Weight != nil {
		msg += "Weight: " + t.Weight.String() + ","
	}
	msg += "Segment List: [ "
	for _, s := range t.Segments {
		msg += s.String() + ","
	}
	msg += " ] }"
	return msg
}

func (t *TunnelEncapSubTLVSRSegmentList) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     EncapSubTLVType `json:"type"`
		Weight   *SegmentListWeight
		Segments []TunnelEncapSubTLVInterface
	}{
		Type:     t.Type,
		Weight:   t.Weight,
		Segments: t.Segments,
	})
}
