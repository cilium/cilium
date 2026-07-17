package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
)

// MUPExtended represents 2-Octet AS Specific BGP MUP Extended Community as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.2.1
// The name predates the draft-ietf sub-type restructuring; the encoding is
// identical to the former Direct-Type Segment Identifier extended community.
type MUPExtended struct {
	SubType    ExtendedCommunityAttrSubType
	SegmentID2 uint16
	SegmentID4 uint32
}

func (e *MUPExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_MUP)
	buf[1] = byte(e.SubType)
	binary.BigEndian.PutUint16(buf[2:4], e.SegmentID2)
	binary.BigEndian.PutUint32(buf[4:8], e.SegmentID4)
	return buf, nil
}

func (e *MUPExtended) String() string {
	return fmt.Sprintf("%d:%d", e.SegmentID2, e.SegmentID4)
}

func (e *MUPExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type      ExtendedCommunityAttrType    `json:"type"`
		Subtype   ExtendedCommunityAttrSubType `json:"subtype"`
		SegmentID string                       `json:"segmend_id"`
	}{
		Type:      t,
		Subtype:   s,
		SegmentID: fmt.Sprintf("%d:%d", e.SegmentID2, e.SegmentID4),
	})
}

func (e *MUPExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_MUP, e.SubType
}

func (e *MUPExtended) Flat() map[string]string {
	return map[string]string{}
}

func NewMUPExtended(subType ExtendedCommunityAttrSubType, sid2 uint16, sid4 uint32) *MUPExtended {
	return &MUPExtended{
		SubType:    subType,
		SegmentID2: sid2,
		SegmentID4: sid4,
	}
}

// MUPIPv4AddressSpecificExtended represents IPv4 Address Specific BGP MUP Extended Community as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.2.2
type MUPIPv4AddressSpecificExtended struct {
	SubType    ExtendedCommunityAttrSubType
	IPv4       netip.Addr
	LocalAdmin uint16
}

func (e *MUPIPv4AddressSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_MUP)
	buf[1] = byte(e.SubType)
	copy(buf[2:6], e.IPv4.AsSlice())
	binary.BigEndian.PutUint16(buf[6:8], e.LocalAdmin)
	return buf, nil
}

func (e *MUPIPv4AddressSpecificExtended) String() string {
	return fmt.Sprintf("%s:%d", e.IPv4, e.LocalAdmin)
}

func (e *MUPIPv4AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type      ExtendedCommunityAttrType    `json:"type"`
		Subtype   ExtendedCommunityAttrSubType `json:"subtype"`
		SegmentID string                       `json:"segment_id"`
	}{
		Type:      t,
		Subtype:   s,
		SegmentID: e.String(),
	})
}

func (e *MUPIPv4AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_MUP, e.SubType
}

func (e *MUPIPv4AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func NewMUPIPv4AddressSpecificExtended(subType ExtendedCommunityAttrSubType, ip netip.Addr, localAdmin uint16) (*MUPIPv4AddressSpecificExtended, error) {
	if !ip.Is4() {
		return nil, fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return &MUPIPv4AddressSpecificExtended{
		SubType:    subType,
		IPv4:       ip,
		LocalAdmin: localAdmin,
	}, nil
}

// MUPFourOctetAsSpecificExtended represents 4-Octet AS Specific BGP MUP Extended Community as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.2.3
type MUPFourOctetAsSpecificExtended struct {
	SubType    ExtendedCommunityAttrSubType
	AS         uint32
	LocalAdmin uint16
}

func (e *MUPFourOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_MUP)
	buf[1] = byte(e.SubType)
	binary.BigEndian.PutUint32(buf[2:6], e.AS)
	binary.BigEndian.PutUint16(buf[6:8], e.LocalAdmin)
	return buf, nil
}

func (e *MUPFourOctetAsSpecificExtended) String() string {
	asUpper := e.AS >> 16
	asLower := e.AS & 0xffff
	return fmt.Sprintf("%d.%d:%d", asUpper, asLower, e.LocalAdmin)
}

func (e *MUPFourOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type      ExtendedCommunityAttrType    `json:"type"`
		Subtype   ExtendedCommunityAttrSubType `json:"subtype"`
		SegmentID string                       `json:"segment_id"`
	}{
		Type:      t,
		Subtype:   s,
		SegmentID: e.String(),
	})
}

func (e *MUPFourOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_MUP, e.SubType
}

func (e *MUPFourOctetAsSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func NewMUPFourOctetAsSpecificExtended(subType ExtendedCommunityAttrSubType, as uint32, localAdmin uint16) *MUPFourOctetAsSpecificExtended {
	return &MUPFourOctetAsSpecificExtended{
		SubType:    subType,
		AS:         as,
		LocalAdmin: localAdmin,
	}
}

func parseMUPExtended(data []byte) (ExtendedCommunityInterface, error) {
	typ := ExtendedCommunityAttrType(data[0])
	if typ != EC_TYPE_MUP {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_MUP: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_MUP_DIRECT_SEG, EC_SUBTYPE_MUP_INTERWORK_SEG:
		sid2 := binary.BigEndian.Uint16(data[2:4])
		sid4 := binary.BigEndian.Uint32(data[4:8])
		return NewMUPExtended(subType, sid2, sid4), nil
	case EC_SUBTYPE_MUP_DIRECT_SEG_IPV4, EC_SUBTYPE_MUP_INTERWORK_SEG_IPV4:
		ipv4, ok := netip.AddrFromSlice(data[2:6])
		if !ok {
			return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("invalid IPv4 address: %x", data[2:6]))
		}
		localAdmin := binary.BigEndian.Uint16(data[6:8])
		return NewMUPIPv4AddressSpecificExtended(subType, ipv4, localAdmin)
	case EC_SUBTYPE_MUP_DIRECT_SEG_4_OCTET_AS, EC_SUBTYPE_MUP_INTERWORK_SEG_4_OCTET_AS:
		as := binary.BigEndian.Uint32(data[2:6])
		localAdmin := binary.BigEndian.Uint16(data[6:8])
		return NewMUPFourOctetAsSpecificExtended(subType, as, localAdmin), nil
	}
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("unknown mup subtype: %d", subType))
}

// BGP MUP SAFI Architecture Type as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1
const (
	MUP_ARCH_TYPE_UNDEFINED = iota
	MUP_ARCH_TYPE_3GPP_5G
)

// BGP MUP SAFI Route Type as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1
const (
	_ = iota
	MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY
	MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY
	MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED
	MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED
)

type MUPRouteTypeInterface interface {
	DecodeFromBytes([]byte, uint16) error
	Serialize() ([]byte, error)
	AFI() uint16
	Len() int
	String() string
	MarshalJSON() ([]byte, error)
	rd() RouteDistinguisherInterface
}

func getMUPRouteType(at uint8, rt uint16) (MUPRouteTypeInterface, error) {
	switch rt {
	case MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY:
		if at == MUP_ARCH_TYPE_3GPP_5G {
			return &MUPInterworkSegmentDiscoveryRoute{}, nil
		}
	case MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY:
		if at == MUP_ARCH_TYPE_3GPP_5G {
			return &MUPDirectSegmentDiscoveryRoute{}, nil
		}
	case MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED:
		if at == MUP_ARCH_TYPE_3GPP_5G {
			return &MUPType1SessionTransformedRoute{}, nil
		}
	case MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED:
		if at == MUP_ARCH_TYPE_3GPP_5G {
			return &MUPType2SessionTransformedRoute{}, nil
		}
	}
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Unknown MUP Architecture and Route type: %d, %d", at, rt))
}

type MUPNLRI struct {
	Afi              uint16
	ArchitectureType uint8
	RouteType        uint16
	Length           uint8
	RouteTypeData    MUPRouteTypeInterface
}

func (n *MUPNLRI) decodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all MUPNLRI bytes available")
	}
	n.ArchitectureType = data[0]
	n.RouteType = binary.BigEndian.Uint16(data[1:3])
	n.Length = data[3]
	data = data[4:]
	if len(data) < int(n.Length) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all MUPNLRI Route type bytes available")
	}
	r, err := getMUPRouteType(n.ArchitectureType, n.RouteType)
	if err != nil {
		return err
	}
	n.RouteTypeData = r
	return n.RouteTypeData.DecodeFromBytes(data[:n.Length], n.Afi)
}

func (n *MUPNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 4)
	buf[0] = n.ArchitectureType
	binary.BigEndian.PutUint16(buf[1:3], n.RouteType)
	buf[3] = n.Length
	tbuf, err := n.RouteTypeData.Serialize()
	if err != nil {
		return nil, err
	}
	// The Length field is a single octet; NewMUPNLRI truncates larger
	// route type data (e.g. carrying too many TLVs) and the mismatch
	// would corrupt the NLRI framing of the whole UPDATE.
	if len(tbuf) != int(n.Length) {
		return nil, fmt.Errorf("MUP NLRI length mismatch: %d bytes of route type data with Length %d", len(tbuf), n.Length)
	}
	return append(buf, tbuf...), nil
}

func (n *MUPNLRI) Len(options ...*MarshallingOption) int {
	return int(n.Length) + 4
}

func (n *MUPNLRI) String() string {
	if n.RouteTypeData != nil {
		return n.RouteTypeData.String()
	}
	return fmt.Sprintf("%d:%d:%d", n.ArchitectureType, n.RouteType, n.Length)
}

func (n *MUPNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ArchitectureType uint8                 `json:"arch_type"`
		RouteType        uint16                `json:"route_type"`
		Value            MUPRouteTypeInterface `json:"value"`
	}{
		ArchitectureType: n.ArchitectureType,
		RouteType:        n.RouteType,
		Value:            n.RouteTypeData,
	})
}

func (n *MUPNLRI) RD() RouteDistinguisherInterface {
	return n.RouteTypeData.rd()
}

func (l *MUPNLRI) Flat() map[string]string {
	return map[string]string{}
}

func NewMUPNLRI(afi uint16, at uint8, rt uint16, data MUPRouteTypeInterface) *MUPNLRI {
	var l uint8
	if data != nil {
		l = uint8(data.Len())
	}
	return &MUPNLRI{
		Afi:              afi,
		ArchitectureType: at,
		RouteType:        rt,
		Length:           l,
		RouteTypeData:    data,
	}
}

func TEIDString(nlri NLRI) string {
	s := ""
	switch n := nlri.(type) {
	case *MUPNLRI:
		switch route := n.RouteTypeData.(type) {
		case *MUPType1SessionTransformedRoute:
			s = route.TEID.String()
		default:
			s = ""
		}
	}
	return s
}

func QFIString(nlri NLRI) string {
	s := ""
	switch n := nlri.(type) {
	case *MUPNLRI:
		switch route := n.RouteTypeData.(type) {
		case *MUPType1SessionTransformedRoute:
			s = fmt.Sprintf("%d", route.QFI)
		default:
			s = ""
		}
	}
	return s
}

func EndpointString(nlri NLRI) string {
	s := ""
	switch n := nlri.(type) {
	case *MUPNLRI:
		switch route := n.RouteTypeData.(type) {
		case *MUPType1SessionTransformedRoute:
			s = route.EndpointAddress.String()
		default:
			s = ""
		}
	}
	return s
}

// MUPInterworkSegmentDiscoveryRoute represents BGP Interwork Segment Discovery route as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.1
type MUPInterworkSegmentDiscoveryRoute struct {
	RD     RouteDistinguisherInterface
	Prefix netip.Prefix
}

func NewMUPInterworkSegmentDiscoveryRoute(rd RouteDistinguisherInterface, prefix netip.Prefix) *MUPNLRI {
	afi := uint16(AFI_IP)
	if prefix.Addr().Is6() {
		afi = AFI_IP6
	}
	return NewMUPNLRI(afi, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, &MUPInterworkSegmentDiscoveryRoute{
		RD:     rd,
		Prefix: prefix,
	})
}

func (r *MUPInterworkSegmentDiscoveryRoute) DecodeFromBytes(data []byte, afi uint16) error {
	if len(data) < 8 {
		return malformedAttrListErr("invalid Interwork Segment Discovery Route length")
	}
	r.RD = GetRouteDistinguisher(data)
	p := r.RD.Len()
	if len(data) < p+1 {
		return malformedAttrListErr("invalid Interwork Segment Discovery Route length")
	}
	bits := int(data[p])
	p += 1
	byteLen := (bits + 7) / 8
	if len(data[p:]) < byteLen {
		return malformedAttrListErr("prefix bytes is short")
	}
	addrLen := 4
	if afi == AFI_IP6 {
		addrLen = 16
	}
	if bits > addrLen*8 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "prefix length is too long")
	}
	b := make([]byte, addrLen)
	if len(data) < p+byteLen {
		return malformedAttrListErr("invalid Interwork Segment Discovery Route length")
	}
	copy(b[:byteLen], data[p:p+byteLen])
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid Prefix: %x", data[p:]))
	}
	r.Prefix = netip.PrefixFrom(addr, bits)
	if r.Prefix.Bits() == -1 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid Prefix: %s", r.Prefix))
	}
	return nil
}

func (r *MUPInterworkSegmentDiscoveryRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if r.RD != nil {
		buf, err = r.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	buf = append(buf, uint8(r.Prefix.Bits()))
	byteLen := (r.Prefix.Bits() + 7) / 8
	buf = append(buf, r.Prefix.Addr().AsSlice()[:byteLen]...)
	return buf, nil
}

func (r *MUPInterworkSegmentDiscoveryRoute) AFI() uint16 {
	if r.Prefix.Addr().Is6() {
		return AFI_IP6
	}
	return AFI_IP
}

func (r *MUPInterworkSegmentDiscoveryRoute) Len() int {
	// RD(8) + PrefixLength(1) + Prefix(variable)
	return 9 + (r.Prefix.Bits()+7)/8
}

func (r *MUPInterworkSegmentDiscoveryRoute) String() string {
	// I-D.draft-ietf-bess-mup-safi-01
	// 3.1.1.  BGP Interwork Segment Discovery route
	// For the purpose of BGP route key processing, only the RD, Prefix Length and Prefix are considered to be part of the prefix in the NLRI.
	return fmt.Sprintf("[type:isd][rd:%s][prefix:%s]", r.RD, r.Prefix)
}

func (r *MUPInterworkSegmentDiscoveryRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD     RouteDistinguisherInterface `json:"rd"`
		Prefix string                      `json:"prefix"`
	}{
		RD:     r.RD,
		Prefix: r.Prefix.String(),
	})
}

func (r *MUPInterworkSegmentDiscoveryRoute) rd() RouteDistinguisherInterface {
	return r.RD
}

// MUPDirectSegmentDiscoveryRoute represents BGP Direct Segment Discovery route as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.2
type MUPDirectSegmentDiscoveryRoute struct {
	RD      RouteDistinguisherInterface
	Address netip.Addr
}

func NewMUPDirectSegmentDiscoveryRoute(rd RouteDistinguisherInterface, address netip.Addr) *MUPNLRI {
	afi := uint16(AFI_IP)
	if address.Is6() {
		afi = AFI_IP6
	}
	return NewMUPNLRI(afi, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, &MUPDirectSegmentDiscoveryRoute{
		RD:      rd,
		Address: address,
	})
}

func (r *MUPDirectSegmentDiscoveryRoute) DecodeFromBytes(data []byte, afi uint16) error {
	if len(data) < 8 {
		return malformedAttrListErr("invalid Direct Segment Discovery Route length")
	}
	r.RD = GetRouteDistinguisher(data)
	rdLen := r.RD.Len()
	if len(data) != 12 && len(data) != 24 {
		return malformedAttrListErr("invalid Direct Segment Discovery Route length")
	}
	if len(data) == 12 {
		address, ok := netip.AddrFromSlice(data[rdLen : rdLen+4])
		if !ok {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid Address: %s", data[rdLen:rdLen+4]))
		}
		r.Address = address
	} else if len(data) == 24 {
		address, ok := netip.AddrFromSlice(data[rdLen : rdLen+16])
		if !ok {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid Address: %d", data[rdLen:rdLen+16]))
		}
		r.Address = address
	}
	return nil
}

func (r *MUPDirectSegmentDiscoveryRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if r.RD != nil {
		buf, err = r.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	buf = append(buf, r.Address.AsSlice()...)
	return buf, nil
}

func (r *MUPDirectSegmentDiscoveryRoute) AFI() uint16 {
	if r.Address.Is6() {
		return AFI_IP6
	}
	return AFI_IP
}

func (r *MUPDirectSegmentDiscoveryRoute) Len() int {
	// RD(8) + Address(4 or 16)
	return 8 + r.Address.BitLen()/8
}

func (r *MUPDirectSegmentDiscoveryRoute) String() string {
	// I-D.draft-ietf-bess-mup-safi-01
	// 3.1.2.  BGP Direct Segment Discovery route
	// For the purpose of BGP route key processing, only the RD and Address are considered to be part of the prefix in the NLRI.
	return fmt.Sprintf("[type:dsd][rd:%s][prefix:%s]", r.RD, r.Address)
}

func (r *MUPDirectSegmentDiscoveryRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD      RouteDistinguisherInterface `json:"rd"`
		Address string                      `json:"address"`
	}{
		RD:      r.RD,
		Address: r.Address.String(),
	})
}

func (r *MUPDirectSegmentDiscoveryRoute) rd() RouteDistinguisherInterface {
	return r.RD
}

// MUPType1SessionTransformedRoute3GPP5G represents 3GPP 5G specific Type 1 Session Transformed (ST) Route as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.3
type MUPType1SessionTransformedRoute struct {
	RD                    RouteDistinguisherInterface
	Prefix                netip.Prefix
	TEID                  netip.Addr
	QFI                   uint8
	EndpointAddressLength uint8
	EndpointAddress       netip.Addr
	SourceAddressLength   uint8
	SourceAddress         *netip.Addr
	// TLVs are not part of the route key and are excluded from String().
	TLVs []MUPTLVInterface
}

func NewMUPType1SessionTransformedRoute(rd RouteDistinguisherInterface, prefix netip.Prefix, teid netip.Addr, qfi uint8, ea netip.Addr, sa *netip.Addr, tlvs ...MUPTLVInterface) *MUPNLRI {
	afi := uint16(AFI_IP)
	if prefix.Addr().Is6() {
		afi = uint16(AFI_IP6)
	}
	r := &MUPType1SessionTransformedRoute{
		RD:                    rd,
		Prefix:                prefix,
		TEID:                  teid,
		QFI:                   qfi,
		EndpointAddressLength: uint8(ea.BitLen()),
		EndpointAddress:       ea,
		TLVs:                  tlvs,
	}
	if sa != nil {
		r.SourceAddressLength = uint8(sa.BitLen())
		r.SourceAddress = sa
	}
	return NewMUPNLRI(afi, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, r)
}

func (r *MUPType1SessionTransformedRoute) DecodeFromBytes(data []byte, afi uint16) error {
	if len(data) < 8 {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
	}
	r.RD = GetRouteDistinguisher(data)
	p := r.RD.Len()
	if len(data) < p+1 {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
	}
	prefixLength := int(data[p])
	p += 1
	addrLen := 0
	switch afi {
	case AFI_IP:
		if prefixLength > 32 {
			return malformedAttrListErr(fmt.Sprintf("Invalid Prefix length: %d", prefixLength))
		}
		addrLen = 4
	case AFI_IP6:
		if prefixLength > 128 {
			return malformedAttrListErr(fmt.Sprintf("Invalid Prefix length: %d", prefixLength))
		}
		addrLen = 16
	default:
		return malformedAttrListErr(fmt.Sprintf("Invalid AFI: %d", afi))
	}
	byteLen := (prefixLength + 7) / 8
	b := make([]byte, addrLen)
	if len(data) < p+byteLen {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
	}
	copy(b[:byteLen], data[p:p+byteLen])
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return malformedAttrListErr(fmt.Sprintf("Invalid Prefix: %x", b))
	}
	r.Prefix = netip.PrefixFrom(addr, prefixLength)
	p += byteLen
	if len(data) < p+4+1+1 {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
	}
	r.TEID, ok = netip.AddrFromSlice(data[p : p+4])
	if !ok {
		return malformedAttrListErr(fmt.Sprintf("Invalid TEID: %x", r.TEID))
	}
	p += 4
	r.QFI = data[p]
	p += 1
	r.EndpointAddressLength = data[p]
	p += 1
	if r.EndpointAddressLength == 32 || r.EndpointAddressLength == 128 {
		if len(data) < p+int(r.EndpointAddressLength/8) {
			return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
		}
		ea, ok := netip.AddrFromSlice(data[p : p+int(r.EndpointAddressLength/8)])
		if !ok {
			return malformedAttrListErr(fmt.Sprintf("Invalid Endpoint Address: %x", data[p:p+int(r.EndpointAddressLength/8)]))
		}
		r.EndpointAddress = ea
	} else {
		return malformedAttrListErr(fmt.Sprintf("Invalid Endpoint Address length: %d", r.EndpointAddressLength))
	}
	p += int(r.EndpointAddressLength / 8)
	if len(data) < p+1 {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
	}
	r.SourceAddressLength = data[p]
	p += 1
	if r.SourceAddressLength == 32 || r.SourceAddressLength == 128 {
		if len(data) < p+int(r.SourceAddressLength/8) {
			return malformedAttrListErr("invalid 3GPP 5G specific Type 1 Session Transformed Route length")
		}
		sa, ok := netip.AddrFromSlice(data[p : p+int(r.SourceAddressLength/8)])
		if !ok {
			return malformedAttrListErr(fmt.Sprintf("Invalid Source Address: %x", data[p:p+int(r.SourceAddressLength/8)]))
		}
		r.SourceAddress = &sa
		p += int(r.SourceAddressLength / 8)
	} else if r.SourceAddressLength != 0 {
		// Any other length would leave the TLV parser below reading
		// from a wrong offset.
		return malformedAttrListErr(fmt.Sprintf("Invalid Source Address length: %d", r.SourceAddressLength))
	}
	// draft-ietf-bess-mup-safi-01 Section 3.1.5 defines no TLV applicable to
	// Type 1 ST routes, but TLVs are still decoded and kept so they are
	// propagated unchanged when re-advertising the route.
	tlvs, err := parseMUPTLVs(data[p:])
	if err != nil {
		return err
	}
	r.TLVs = tlvs
	return nil
}

func (r *MUPType1SessionTransformedRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if r.RD != nil {
		buf, err = r.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	buf = append(buf, byte(r.Prefix.Bits()))
	byteLen := (r.Prefix.Bits() + 7) / 8
	buf = append(buf, r.Prefix.Addr().AsSlice()[:byteLen]...)
	buf = append(buf, r.TEID.AsSlice()...)
	buf = append(buf, r.QFI)
	buf = append(buf, r.EndpointAddressLength)
	buf = append(buf, r.EndpointAddress.AsSlice()...)
	buf = append(buf, r.SourceAddressLength)
	if r.SourceAddressLength > 0 {
		buf = append(buf, r.SourceAddress.AsSlice()...)
	}
	return serializeMUPTLVs(buf, r.TLVs)
}

func (r *MUPType1SessionTransformedRoute) AFI() uint16 {
	if r.Prefix.Addr().Is6() {
		return AFI_IP6
	}
	return AFI_IP
}

func (r *MUPType1SessionTransformedRoute) Len() int {
	// RD(8) + PrefixLength(1) + Prefix(variable)
	// + TEID(4) + QFI(1) + EndpointAddressLength(1) + EndpointAddress(4 or 16) + SourceAddressLength(1) + SourceAddress(4 or 16)
	// + TLVs(variable)
	l := 16 + (r.Prefix.Bits()+7)/8 + int(r.EndpointAddressLength/8)
	if r.SourceAddressLength > 0 {
		l += int(r.SourceAddressLength / 8)
	}
	return l + mupTLVsLen(r.TLVs)
}

func (r *MUPType1SessionTransformedRoute) String() string {
	// I-D.draft-ietf-bess-mup-safi-01
	// 3.1.3.  BGP Type 1 Session Transformed (ST) Route
	// For the purpose of BGP route key processing, only the RD, Prefix Length and Prefix are considered to be part of the prefix in the NLRI.
	return fmt.Sprintf("[type:t1st][rd:%s][prefix:%s]", r.RD, r.Prefix)
}

func (r *MUPType1SessionTransformedRoute) MarshalJSON() ([]byte, error) {
	d := struct {
		RD              RouteDistinguisherInterface `json:"rd"`
		Prefix          string                      `json:"prefix"`
		TEID            string                      `json:"teid"`
		QFI             uint8                       `json:"qfi"`
		EndpointAddress string                      `json:"endpoint_address"`
		SourceAddress   string                      `json:"source_address"`
		TLVs            []MUPTLVInterface           `json:"tlvs,omitempty"`
	}{
		RD:              r.RD,
		Prefix:          r.Prefix.String(),
		TEID:            r.TEID.String(),
		QFI:             r.QFI,
		EndpointAddress: r.EndpointAddress.String(),
		TLVs:            r.TLVs,
	}
	if r.SourceAddress != nil {
		d.SourceAddress = r.SourceAddress.String()
	}
	return json.Marshal(d)
}

func (r *MUPType1SessionTransformedRoute) rd() RouteDistinguisherInterface {
	return r.RD
}

// MUPType2SessionTransformedRoute represents 3GPP 5G specific Type 2 Session Transformed (ST) Route as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.4
type MUPType2SessionTransformedRoute struct {
	RD                    RouteDistinguisherInterface
	EndpointAddressLength uint8
	EndpointAddress       netip.Addr
	TEID                  netip.Addr
	// TLVs are not part of the route key and are excluded from String().
	TLVs []MUPTLVInterface
}

func NewMUPType2SessionTransformedRoute(rd RouteDistinguisherInterface, eaLen uint8, ea netip.Addr, teid netip.Addr, tlvs ...MUPTLVInterface) *MUPNLRI {
	afi := uint16(AFI_IP)
	if ea.Is6() {
		afi = AFI_IP6
	}
	return NewMUPNLRI(afi, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, &MUPType2SessionTransformedRoute{
		RD:                    rd,
		EndpointAddressLength: eaLen,
		EndpointAddress:       ea,
		TEID:                  teid,
		TLVs:                  tlvs,
	})
}

func (r *MUPType2SessionTransformedRoute) DecodeFromBytes(data []byte, afi uint16) error {
	if len(data) < 8 {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 2 Session Transformed Route length")
	}
	r.RD = GetRouteDistinguisher(data)
	p := r.RD.Len()
	if len(data) < p+1 {
		return malformedAttrListErr("invalid 3GPP 5G specific Type 2 Session Transformed Route length")
	}
	r.EndpointAddressLength = data[p]
	if afi == AFI_IP && r.EndpointAddressLength > 64 || afi == AFI_IP6 && r.EndpointAddressLength > 160 {
		return malformedAttrListErr(fmt.Sprintf("Invalid Endpoint Address Length: %d", r.EndpointAddressLength))
	}
	p += 1
	var ea netip.Addr
	var ok bool
	teidLen := 0
	switch afi {
	case AFI_IP:
		if len(data) < p+4 {
			return malformedAttrListErr("invalid 3GPP 5G specific Type 2 Session Transformed Route length")
		}
		ea, ok = netip.AddrFromSlice(data[p : p+4])
		if !ok {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid Endpoint Address: %x", data[p:p+int(r.EndpointAddressLength/8)]))
		}
		p += 4
		teidLen = int(r.EndpointAddressLength) - 32
	case AFI_IP6:
		if len(data) < p+16 {
			return malformedAttrListErr("invalid 3GPP 5G specific Type 2 Session Transformed Route length")
		}
		ea, ok = netip.AddrFromSlice(data[p : p+16])
		if !ok {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid Endpoint Address: %x", data[p:p+int(r.EndpointAddressLength/8)]))
		}
		p += 16
		teidLen = int(r.EndpointAddressLength) - 128
	default:
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid AFI: %d", afi))
	}
	r.EndpointAddress = ea
	if teidLen > 0 {
		l := (teidLen + 7) / 8
		b := make([]byte, 4)
		if len(data) < p+l {
			return malformedAttrListErr("invalid 3GPP 5G specific Type 2 Session Transformed Route length")
		}
		copy(b[:l], data[p:p+l])
		a, ok := netip.AddrFromSlice(b)
		if !ok {
			return malformedAttrListErr(fmt.Sprintf("Invalid TEID: %x", data[p:p+l]))
		}
		r.TEID = a
		p += l
	} else {
		r.TEID = netip.AddrFrom4([4]byte{0, 0, 0, 0})
	}
	tlvs, err := parseMUPTLVs(data[p:])
	if err != nil {
		return err
	}
	r.TLVs = tlvs
	return nil
}

func (r *MUPType2SessionTransformedRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if r.RD != nil {
		buf, err = r.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	buf = append(buf, r.EndpointAddressLength)
	buf = append(buf, r.EndpointAddress.AsSlice()...)
	teidLen := int(r.EndpointAddressLength) - r.EndpointAddress.BitLen()
	if teidLen > 0 {
		byteLen := (teidLen + 7) / 8
		buf = append(buf, r.TEID.AsSlice()[:byteLen]...)
	}
	return serializeMUPTLVs(buf, r.TLVs)
}

func (r *MUPType2SessionTransformedRoute) AFI() uint16 {
	if r.EndpointAddress.Is6() {
		return AFI_IP6
	}
	return AFI_IP
}

func (r *MUPType2SessionTransformedRoute) Len() int {
	// RD(8) + EndpointAddressLength(1) + EndpointAddress(4 or 16)
	// + TEID(0-4)
	// Endpoint Address Length includes TEID Length
	// + TLVs(variable)
	return 9 + (int(r.EndpointAddressLength)+7)/8 + mupTLVsLen(r.TLVs)
}

func (r *MUPType2SessionTransformedRoute) String() string {
	// I-D.draft-ietf-bess-mup-safi-01
	// 3.1.4.  BGP Type 2 Session Transformed (ST) Route
	// For the purpose of BGP route key processing, only the RD, Endpoint Address and Architecture specific Endpoint Identifier are considered to be part of the prefix in the NLRI.
	return fmt.Sprintf("[type:t2st][rd:%s][endpoint-address-length:%d][endpoint:%s][teid:%s]", r.RD, r.EndpointAddressLength, r.EndpointAddress, r.TEID)
}

func (r *MUPType2SessionTransformedRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD                    RouteDistinguisherInterface `json:"rd"`
		EndpointAddressLength uint8                       `json:"endpoint_address_length"`
		EndpointAddress       string                      `json:"endpoint_address"`
		TEID                  string                      `json:"teid"`
		TLVs                  []MUPTLVInterface           `json:"tlvs,omitempty"`
	}{
		RD:                    r.RD,
		EndpointAddressLength: r.EndpointAddressLength,
		EndpointAddress:       r.EndpointAddress.String(),
		TEID:                  r.TEID.String(),
		TLVs:                  r.TLVs,
	})
}

func (r *MUPType2SessionTransformedRoute) rd() RouteDistinguisherInterface {
	return r.RD
}

// BGP MUP SAFI TLV Types for ST Routes as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.5
const (
	MUP_TLV_TYPE_3GPP_5G_SESSION_PARAMETERS uint8 = 1
	MUP_TLV_TYPE_INTERWORK_ENDPOINT         uint8 = 2
	MUP_TLV_TYPE_SOURCE_ADDRESS             uint8 = 3
)

type MUPTLVInterface interface {
	Type() uint8
	Len() int
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
}

// MUPSessionParametersTLV represents 3gpp-5g Session Parameters TLV as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.5.1
type MUPSessionParametersTLV struct {
	TEID netip.Addr
	QFI  uint8
}

func NewMUPSessionParametersTLV(teid netip.Addr, qfi uint8) *MUPSessionParametersTLV {
	return &MUPSessionParametersTLV{
		TEID: teid,
		QFI:  qfi,
	}
}

func (t *MUPSessionParametersTLV) Type() uint8 {
	return MUP_TLV_TYPE_3GPP_5G_SESSION_PARAMETERS
}

func (t *MUPSessionParametersTLV) Len() int {
	// Type(1) + Length(1) + TEID(4) + QFI(1)
	return 7
}

func (t *MUPSessionParametersTLV) DecodeFromBytes(value []byte) error {
	if len(value) != 5 {
		return malformedAttrListErr(fmt.Sprintf("invalid 3gpp-5g Session Parameters TLV length: %d", len(value)))
	}
	teid, ok := netip.AddrFromSlice(value[:4])
	if !ok {
		return malformedAttrListErr(fmt.Sprintf("invalid TEID: %x", value[:4]))
	}
	t.TEID = teid
	t.QFI = value[4]
	return nil
}

func (t *MUPSessionParametersTLV) Serialize() ([]byte, error) {
	if !t.TEID.Is4() {
		return nil, fmt.Errorf("invalid TEID: %s", t.TEID)
	}
	buf := make([]byte, 2, 7)
	buf[0] = t.Type()
	buf[1] = 5
	buf = append(buf, t.TEID.AsSlice()...)
	buf = append(buf, t.QFI)
	return buf, nil
}

func (t *MUPSessionParametersTLV) String() string {
	return fmt.Sprintf("[teid:%s][qfi:%d]", t.TEID, t.QFI)
}

func (t *MUPSessionParametersTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type uint8  `json:"type"`
		TEID string `json:"teid"`
		QFI  uint8  `json:"qfi"`
	}{
		Type: t.Type(),
		TEID: t.TEID.String(),
		QFI:  t.QFI,
	})
}

// MUPInterworkEndpointTLV represents Interwork Endpoint TLV as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.5.2
type MUPInterworkEndpointTLV struct {
	Address netip.Addr
}

func NewMUPInterworkEndpointTLV(address netip.Addr) *MUPInterworkEndpointTLV {
	return &MUPInterworkEndpointTLV{
		Address: address,
	}
}

func (t *MUPInterworkEndpointTLV) Type() uint8 {
	return MUP_TLV_TYPE_INTERWORK_ENDPOINT
}

func (t *MUPInterworkEndpointTLV) Len() int {
	// Type(1) + Length(1) + Address(4 or 16)
	return 2 + t.Address.BitLen()/8
}

func (t *MUPInterworkEndpointTLV) DecodeFromBytes(value []byte) error {
	if len(value) != 4 && len(value) != 16 {
		return malformedAttrListErr(fmt.Sprintf("invalid Interwork Endpoint TLV length: %d", len(value)))
	}
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		return malformedAttrListErr(fmt.Sprintf("invalid Interwork Endpoint TLV address: %x", value))
	}
	t.Address = address
	return nil
}

func (t *MUPInterworkEndpointTLV) Serialize() ([]byte, error) {
	if !t.Address.IsValid() {
		return nil, fmt.Errorf("invalid Interwork Endpoint TLV address: %s", t.Address)
	}
	buf := make([]byte, 2, t.Len())
	buf[0] = t.Type()
	buf[1] = uint8(t.Address.BitLen() / 8)
	buf = append(buf, t.Address.AsSlice()...)
	return buf, nil
}

func (t *MUPInterworkEndpointTLV) String() string {
	return fmt.Sprintf("[interwork-endpoint:%s]", t.Address)
}

func (t *MUPInterworkEndpointTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    uint8  `json:"type"`
		Address string `json:"address"`
	}{
		Type:    t.Type(),
		Address: t.Address.String(),
	})
}

// MUPSourceAddressTLV represents Source Address TLV as described in
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.5.3
type MUPSourceAddressTLV struct {
	Address netip.Addr
}

func NewMUPSourceAddressTLV(address netip.Addr) *MUPSourceAddressTLV {
	return &MUPSourceAddressTLV{
		Address: address,
	}
}

func (t *MUPSourceAddressTLV) Type() uint8 {
	return MUP_TLV_TYPE_SOURCE_ADDRESS
}

func (t *MUPSourceAddressTLV) Len() int {
	// Type(1) + Length(1) + Address(4 or 16)
	return 2 + t.Address.BitLen()/8
}

func (t *MUPSourceAddressTLV) DecodeFromBytes(value []byte) error {
	if len(value) != 4 && len(value) != 16 {
		return malformedAttrListErr(fmt.Sprintf("invalid Source Address TLV length: %d", len(value)))
	}
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		return malformedAttrListErr(fmt.Sprintf("invalid Source Address TLV address: %x", value))
	}
	t.Address = address
	return nil
}

func (t *MUPSourceAddressTLV) Serialize() ([]byte, error) {
	if !t.Address.IsValid() {
		return nil, fmt.Errorf("invalid Source Address TLV address: %s", t.Address)
	}
	buf := make([]byte, 2, t.Len())
	buf[0] = t.Type()
	buf[1] = uint8(t.Address.BitLen() / 8)
	buf = append(buf, t.Address.AsSlice()...)
	return buf, nil
}

func (t *MUPSourceAddressTLV) String() string {
	return fmt.Sprintf("[source-address:%s]", t.Address)
}

func (t *MUPSourceAddressTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    uint8  `json:"type"`
		Address string `json:"address"`
	}{
		Type:    t.Type(),
		Address: t.Address.String(),
	})
}

// MUPUnknownTLV keeps a TLV of an unknown type as-is so that it is
// propagated unchanged when re-advertising the route, as required by
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.3
type MUPUnknownTLV struct {
	TLVType uint8
	Value   []byte
}

func NewMUPUnknownTLV(typ uint8, value []byte) *MUPUnknownTLV {
	return &MUPUnknownTLV{
		TLVType: typ,
		Value:   value,
	}
}

func (t *MUPUnknownTLV) Type() uint8 {
	return t.TLVType
}

func (t *MUPUnknownTLV) Len() int {
	return 2 + len(t.Value)
}

func (t *MUPUnknownTLV) DecodeFromBytes(value []byte) error {
	t.Value = append([]byte(nil), value...)
	return nil
}

func (t *MUPUnknownTLV) Serialize() ([]byte, error) {
	if len(t.Value) > 255 {
		return nil, fmt.Errorf("invalid MUP TLV value length: %d", len(t.Value))
	}
	buf := make([]byte, 2, t.Len())
	buf[0] = t.TLVType
	buf[1] = uint8(len(t.Value))
	buf = append(buf, t.Value...)
	return buf, nil
}

func (t *MUPUnknownTLV) String() string {
	return fmt.Sprintf("[unknown-tlv-type:%d][value:%x]", t.TLVType, t.Value)
}

func (t *MUPUnknownTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  uint8  `json:"type"`
		Value []byte `json:"value"`
	}{
		Type:  t.TLVType,
		Value: t.Value,
	})
}

// parseMUPTLVs parses the optional TLVs following the mandatory fields of
// Type 1 and Type 2 Session Transformed routes.
// https://datatracker.ietf.org/doc/html/draft-ietf-bess-mup-safi-01#section-3.1.3
// requires zero remaining octets to mean no TLVs, and a single remaining
// octet cannot hold a TLV header, making the NLRI malformed.
func parseMUPTLVs(data []byte) ([]MUPTLVInterface, error) {
	var tlvs []MUPTLVInterface
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, malformedAttrListErr("invalid MUP TLV: no room for Type and Length")
		}
		typ := data[0]
		l := int(data[1])
		if len(data) < 2+l {
			return nil, malformedAttrListErr(fmt.Sprintf("invalid MUP TLV: declared length %d exceeds remaining %d octets", l, len(data)-2))
		}
		var tlv MUPTLVInterface
		switch typ {
		case MUP_TLV_TYPE_3GPP_5G_SESSION_PARAMETERS:
			tlv = &MUPSessionParametersTLV{}
		case MUP_TLV_TYPE_INTERWORK_ENDPOINT:
			tlv = &MUPInterworkEndpointTLV{}
		case MUP_TLV_TYPE_SOURCE_ADDRESS:
			tlv = &MUPSourceAddressTLV{}
		default:
			tlv = &MUPUnknownTLV{TLVType: typ}
		}
		if err := tlv.DecodeFromBytes(data[2 : 2+l]); err != nil {
			return nil, err
		}
		tlvs = append(tlvs, tlv)
		data = data[2+l:]
	}
	return tlvs, nil
}

func serializeMUPTLVs(buf []byte, tlvs []MUPTLVInterface) ([]byte, error) {
	for _, t := range tlvs {
		b, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

func mupTLVsLen(tlvs []MUPTLVInterface) int {
	l := 0
	for _, t := range tlvs {
		l += t.Len()
	}
	return l
}
