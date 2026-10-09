package bgp

// This file implements the BGP-LS SR Policy Candidate Path NLRI (type 5)
// and the related BGP-LS Attribute TLVs defined in RFC 9857
// "Advertisement of Segment Routing Policies Using BGP Link-State".
//
// Implemented:
//   - NLRI type 5 with the SR Policy Candidate Path Descriptor TLV (554)
//   - SR Binding SID TLV (1201), SRv6 Binding SID TLV (1212)
//   - SR Candidate Path State TLV (1202)
//   - SR Candidate Path Name TLV (1203), SR Policy Name TLV (1213)
//   - SR Segment List TLV (1205) with its sub-TLVs: SR Segment (1206),
//     SR Segment List Metric (1207), SR Segment List Bandwidth (1216) and
//     SR Segment List Identifier (1217)
//   - SR Candidate Path Constraints TLV (1204) with its sub-TLVs: SR
//     Affinity Constraint (1208), SR SRLG Constraint (1209), SR Bandwidth
//     Constraint (1210), SR Disjoint Group Constraint (1211), SR
//     Bidirectional Group Constraint (1214) and SR Metric Constraint (1215)
//
// Unknown TLVs nested in these are kept opaque and re-serialized as received.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// errLsSkipTLV is returned by a sub-TLV decoder when the sub-TLV is well
// formed at the TLV level but carries content this implementation cannot
// interpret (e.g. an unknown SR Segment Type). Keep these sub-TLVs opaque
// so a speaker can still forward the complete attribute.
var errLsSkipTLV = errors.New("skip unsupported BGP-LS sub-TLV")

// lsMplsLabelFromField decodes an MPLS label from the 4-octet SID/BSID field
// layout used by RFC 9857: Label (20 bits) | TC (3) | S (1) | TTL (8).
// TC, S and TTL are reserved and ignored.
func lsMplsLabelFromField(b []byte) uint32 {
	return binary.BigEndian.Uint32(b[:4]) >> 12
}

// lsMplsLabelToField encodes an MPLS label into the 4-octet RFC 9857 field
// layout with the reserved TC, S and TTL bits cleared.
func lsMplsLabelToField(label uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, label<<12)
	return b
}

// lsValidBandwidth reports whether a received bandwidth value is usable.
// A negative, NaN or infinite value stays in the TLV list, so it is still
// re-serialized as received, but is kept out of the model (NaN and the
// infinities cannot be marshalled to JSON at all).
func lsValidBandwidth(bw float32) bool {
	return bw >= 0 && !math.IsNaN(float64(bw)) && !math.IsInf(float64(bw), 0)
}

// lsAddrBytes returns addr as a fixed-size slice of n (4 or 16) bytes. An
// invalid address yields n zero bytes.
func lsAddrBytes(addr netip.Addr, n int) []byte {
	if !addr.IsValid() {
		return make([]byte, n)
	}
	if n == 4 {
		a := addr.Unmap().As4()
		return a[:]
	}
	a := addr.As16()
	return a[:]
}

// lsWalkSubTLVs iterates over a sequence of BGP-LS sub-TLVs. alloc returns
// the concrete TLV for a type, or nil to keep an unknown type opaque.
func lsWalkSubTLVs(data []byte, alloc func(LsTLVType) LsTLVInterface) ([]LsTLVInterface, error) {
	subTLVs := []LsTLVInterface{}

	for len(data) >= tlvHdrLen {
		hdr := &LsTLV{}
		if _, err := hdr.DecodeFromBytes(data); err != nil {
			return nil, err
		}

		sub := alloc(hdr.Type)
		if sub == nil {
			sub = &lsTLVUnknown{}
		}

		if err := sub.DecodeFromBytes(data); err != nil {
			if errors.Is(err, errLsSkipTLV) {
				sub = &lsTLVUnknown{}
				if err := sub.DecodeFromBytes(data); err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
		subTLVs = append(subTLVs, sub)
		data = data[hdr.Len():]
	}

	if len(data) != 0 {
		return nil, malformedAttrListErr("Truncated BGP-LS sub-TLV header")
	}
	return subTLVs, nil
}

func lsSerializeSubTLVs(subTLVs []LsTLVInterface) ([]byte, error) {
	buf := []byte{}
	for _, sub := range subTLVs {
		ser, err := sub.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ser...)
	}
	return buf, nil
}

func lsSubTLVsLen(subTLVs []LsTLVInterface) int {
	n := 0
	for _, sub := range subTLVs {
		n += sub.Len()
	}
	return n
}

// lsSrv6SubTLVAlloc allocates the SRv6 sub-TLVs (RFC 9514) that RFC 9857
// allows inside the SRv6 Binding SID TLV and the SR Segment sub-TLV.
func lsSrv6SubTLVAlloc(t LsTLVType) LsTLVInterface {
	switch t {
	case LS_TLV_SRV6_ENDPOINT_BEHAVIOR:
		return &LsTLVSrv6EndpointBehavior{}
	case LS_TLV_SRV6_SID_STRUCTURE:
		return &LsTLVSrv6SIDStructure{}
	}
	return nil
}

func lsSrv6SubTLVsFromModel(eb *LsSrv6EndpointBehavior, ss *LsSrv6SIDStructure) []LsTLVInterface {
	subTLVs := []LsTLVInterface{}
	if eb != nil {
		subTLVs = append(subTLVs, NewLsTLVSrv6EndpointBehavior(eb))
	}
	if ss != nil {
		subTLVs = append(subTLVs, NewLsTLVSrv6SIDStructure(ss))
	}
	return subTLVs
}

func lsSrv6SubTLVsToModel(subTLVs []LsTLVInterface) (*LsSrv6EndpointBehavior, *LsSrv6SIDStructure) {
	var eb *LsSrv6EndpointBehavior
	var ss *LsSrv6SIDStructure
	for _, sub := range subTLVs {
		switch v := sub.(type) {
		case *LsTLVSrv6EndpointBehavior:
			if eb == nil {
				eb = v.Extract()
			}
		case *LsTLVSrv6SIDStructure:
			if ss == nil {
				ss = v.Extract()
			}
		}
	}
	return eb, ss
}

// SR Policy Candidate Path Descriptor TLV (554), RFC 9857 Section 4.1

const (
	lsSrPolicyCPDescFlagEndpointV6   uint8 = 1 << 7 // E-Flag
	lsSrPolicyCPDescFlagOriginatorV6 uint8 = 1 << 6 // O-Flag
)

// LsSrPolicyCandidatePathDescriptor is the decoded content of the SR Policy
// Candidate Path Descriptor TLV.
type LsSrPolicyCandidatePathDescriptor struct {
	ProtocolOrigin    uint8      `json:"protocol_origin"`
	Endpoint          netip.Addr `json:"endpoint"`
	Color             uint32     `json:"color"`
	OriginatorASN     uint32     `json:"originator_asn"`
	OriginatorAddress netip.Addr `json:"originator_address"`
	Discriminator     uint32     `json:"discriminator"`
}

func (d *LsSrPolicyCandidatePathDescriptor) String() string {
	return fmt.Sprintf("{Endpoint: %s Color: %d Origin: %d Originator: %d/%s Discriminator: %d}",
		d.Endpoint, d.Color, d.ProtocolOrigin, d.OriginatorASN, d.OriginatorAddress, d.Discriminator)
}

type LsTLVSrPolicyCandidatePathDescriptor struct {
	LsTLV
	ProtocolOrigin    uint8
	Flags             uint8
	Endpoint          netip.Addr
	Color             uint32
	OriginatorASN     uint32
	OriginatorAddress netip.Addr
	Discriminator     uint32
}

func lsSrPolicyCPDescLen(endpoint, originator netip.Addr) uint16 {
	n := 4 + 4 + 4 + 4
	if endpoint.Is6() {
		n += 16
	} else {
		n += 4
	}
	if originator.Is6() {
		n += 16
	} else {
		n += 4
	}
	return uint16(n)
}

func NewLsTLVSrPolicyCandidatePathDescriptor(d *LsSrPolicyCandidatePathDescriptor) *LsTLVSrPolicyCandidatePathDescriptor {
	endpoint := d.Endpoint.Unmap()
	originator := d.OriginatorAddress.Unmap()

	var flags uint8
	if endpoint.Is6() {
		flags |= lsSrPolicyCPDescFlagEndpointV6
	}
	if originator.Is6() {
		flags |= lsSrPolicyCPDescFlagOriginatorV6
	}

	return &LsTLVSrPolicyCandidatePathDescriptor{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_POLICY_CP_DESC,
			Length: lsSrPolicyCPDescLen(endpoint, originator),
		},
		ProtocolOrigin:    d.ProtocolOrigin,
		Flags:             flags,
		Endpoint:          endpoint,
		Color:             d.Color,
		OriginatorASN:     d.OriginatorASN,
		OriginatorAddress: originator,
		Discriminator:     d.Discriminator,
	}
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) Extract() *LsSrPolicyCandidatePathDescriptor {
	return &LsSrPolicyCandidatePathDescriptor{
		ProtocolOrigin:    l.ProtocolOrigin,
		Endpoint:          l.Endpoint,
		Color:             l.Color,
		OriginatorASN:     l.OriginatorASN,
		OriginatorAddress: l.OriginatorAddress,
		Discriminator:     l.Discriminator,
	}
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_POLICY_CP_DESC {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 4 {
		return malformedAttrListErr("Incorrect SR Policy Candidate Path Descriptor length")
	}

	l.ProtocolOrigin = value[0]
	l.Flags = value[1]
	// value[2:4] is reserved and ignored.

	epLen := 4
	if l.Flags&lsSrPolicyCPDescFlagEndpointV6 != 0 {
		epLen = 16
	}
	origLen := 4
	if l.Flags&lsSrPolicyCPDescFlagOriginatorV6 != 0 {
		origLen = 16
	}

	if len(value) != 4+epLen+4+4+origLen+4 {
		return malformedAttrListErr("Incorrect SR Policy Candidate Path Descriptor length")
	}

	p := 4
	l.Endpoint, _ = netip.AddrFromSlice(value[p : p+epLen])
	p += epLen
	l.Color = binary.BigEndian.Uint32(value[p : p+4])
	p += 4
	l.OriginatorASN = binary.BigEndian.Uint32(value[p : p+4])
	p += 4
	l.OriginatorAddress, _ = netip.AddrFromSlice(value[p : p+origLen])
	p += origLen
	l.Discriminator = binary.BigEndian.Uint32(value[p : p+4])

	return nil
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) Serialize() ([]byte, error) {
	if !l.Endpoint.IsValid() || !l.OriginatorAddress.IsValid() {
		return nil, malformedAttrListErr("SR Policy Candidate Path Descriptor requires endpoint and originator address")
	}

	// The E and O flags are derived from the address families so that the
	// encoded widths always agree with the flags.
	flags := l.Flags &^ (lsSrPolicyCPDescFlagEndpointV6 | lsSrPolicyCPDescFlagOriginatorV6)
	epLen, origLen := 4, 4
	if l.Endpoint.Unmap().Is6() {
		flags |= lsSrPolicyCPDescFlagEndpointV6
		epLen = 16
	}
	if l.OriginatorAddress.Unmap().Is6() {
		flags |= lsSrPolicyCPDescFlagOriginatorV6
		origLen = 16
	}

	buf := make([]byte, 0, 4+epLen+4+4+origLen+4)
	buf = append(buf, l.ProtocolOrigin, flags, 0, 0)
	buf = append(buf, lsAddrBytes(l.Endpoint, epLen)...)
	buf = binary.BigEndian.AppendUint32(buf, l.Color)
	buf = binary.BigEndian.AppendUint32(buf, l.OriginatorASN)
	buf = append(buf, lsAddrBytes(l.OriginatorAddress, origLen)...)
	buf = binary.BigEndian.AppendUint32(buf, l.Discriminator)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) String() string {
	return l.Extract().String()
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrPolicyCandidatePathDescriptor
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Policy Candidate Path NLRI (type 5), RFC 9857 Section 4

// LsSrPolicyCandidatePathNLRI carries the headend Local Node Descriptors TLV
// (256) and the SR Policy Candidate Path Descriptor TLV (554). TLVs holds
// every received TLV in wire order, unknown and repeated ones included, so
// that they are preserved and propagated (RFC 9552 Section 5.1).
type LsSrPolicyCandidatePathNLRI struct {
	LsNLRI
	LocalNodeDesc     LsTLVInterface
	CandidatePathDesc LsTLVInterface
	TLVs              []LsTLVInterface
}

// String returns a representation that is unique per candidate path: it is
// used as the RIB destination key for BGP-LS routes, so every descriptor
// field and the NLRI header identifiers must be part of it.
func (l *LsSrPolicyCandidatePathNLRI) String() string {
	if l.LocalNodeDesc == nil || l.CandidatePathDesc == nil {
		return "SRPOLICY_CP { EMPTY }"
	}

	local, ok := l.LocalNodeDesc.(*LsTLVNodeDescriptor)
	if !ok {
		return "SRPOLICY_CP { INVALID }"
	}
	cpTLV, ok := l.CandidatePathDesc.(*LsTLVSrPolicyCandidatePathDescriptor)
	if !ok {
		return "SRPOLICY_CP { INVALID }"
	}
	cp := cpTLV.Extract()

	// Preserved unknown and repeated TLVs are part of the key too.
	var unknown strings.Builder
	for _, tlv := range l.TLVs {
		if u, ok := tlv.(*lsTLVUnknown); ok {
			fmt.Fprintf(&unknown, " TLV %d: %x", u.Type, u.Value)
		}
	}

	return fmt.Sprintf("SRPOLICY_CP { LOCAL_NODE: %s ENDPOINT: %s COLOR: %d ORIGIN: %d ORIGINATOR: %d/%s DISCRIMINATOR: %d%s %s:%d }",
		lsSrPolicyHeadendString(local), cp.Endpoint, cp.Color, cp.ProtocolOrigin, cp.OriginatorASN, cp.OriginatorAddress, cp.Discriminator,
		unknown.String(), l.ProtocolID.String(), l.Identifier)
}

// lsSrPolicyHeadendString renders the headend node descriptor sub-TLVs as
// received, in wire order. LsNodeDescriptor.String omits the IGP fields
// when a BGP Router-ID is present, but every sub-TLV is part of this NLRI's
// key and must distinguish destinations in the RIB. Only the sub-TLVs that
// were received are printed, so a descriptor carrying an OSPF area of 0 is
// told apart from one carrying no area at all.
func lsSrPolicyHeadendString(nd *LsTLVNodeDescriptor) string {
	fields := make([]string, 0, len(nd.SubTLVs))
	for _, sub := range nd.SubTLVs {
		switch v := sub.(type) {
		case *LsTLVAutonomousSystem:
			fields = append(fields, fmt.Sprintf("ASN: %d", v.ASN))
		case *LsTLVBgpLsID:
			fields = append(fields, fmt.Sprintf("BGP LS ID: %d", v.BGPLsID))
		case *LsTLVOspfAreaID:
			fields = append(fields, fmt.Sprintf("OSPF AREA: %d", v.AreaID))
		case *LsTLVIgpRouterID:
			id, _ := parseIGPRouterID(v.RouterID)
			fields = append(fields, fmt.Sprintf("IGP ROUTER ID: %s", id))
		case *LsTLVBgpRouterID:
			fields = append(fields, fmt.Sprintf("BGP ROUTER ID: %s", v.RouterID))
		case *LsTLVBgpConfederationMember:
			fields = append(fields, fmt.Sprintf("CONFEDERATION: %d", v.BgpConfederationMember))
		case *LsTLVLocalIPv4RouterID:
			fields = append(fields, fmt.Sprintf("IPv4 ROUTER ID: %s", v.IP))
		case *LsTLVLocalIPv6RouterID:
			fields = append(fields, fmt.Sprintf("IPv6 ROUTER ID: %s", v.IP))
		case *lsTLVUnknown:
			fields = append(fields, fmt.Sprintf("TLV %d: %x", v.Type, v.Value))
		}
	}
	return "{" + strings.Join(fields, ", ") + "}"
}

func (l *LsSrPolicyCandidatePathNLRI) DecodeFromBytes(data []byte) error {
	if err := l.LsNLRI.DecodeFromBytes(data); err != nil {
		return err
	}

	tlvs := data[lsNLRIHdrLen:]

	for len(tlvs) >= tlvHdrLen {
		hdr := &LsTLV{}
		if _, err := hdr.DecodeFromBytes(tlvs); err != nil {
			return err
		}

		var tlv LsTLVInterface
		switch hdr.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			if l.LocalNodeDesc == nil {
				nd := &LsTLVNodeDescriptor{}
				if err := nd.decodeFromBytes(tlvs, true); err != nil {
					return err
				}
				l.LocalNodeDesc = nd
				l.TLVs = append(l.TLVs, nd)
				tlvs = tlvs[hdr.Len():]
				continue
			}
		case LS_TLV_SR_POLICY_CP_DESC:
			if l.CandidatePathDesc == nil {
				tlv = &LsTLVSrPolicyCandidatePathDescriptor{}
			}
		}

		// The first instance of a TLV is used (RFC 9857). Unknown TLVs and
		// repeated instances are kept as opaque TLVs so that they are
		// preserved and propagated (RFC 9552 Section 5.1).
		if tlv == nil {
			tlv = &lsTLVUnknown{}
		}

		if err := tlv.DecodeFromBytes(tlvs); err != nil {
			return err
		}
		l.TLVs = append(l.TLVs, tlv)
		tlvs = tlvs[tlv.Len():]

		if hdr.Type == LS_TLV_SR_POLICY_CP_DESC && l.CandidatePathDesc == nil {
			l.CandidatePathDesc = tlv
		}
	}

	if l.LocalNodeDesc == nil || l.CandidatePathDesc == nil {
		return malformedAttrListErr("Required TLV missing")
	}

	return nil
}

func (l *LsSrPolicyCandidatePathNLRI) Serialize() ([]byte, error) {
	if l.LocalNodeDesc == nil || l.CandidatePathDesc == nil {
		return nil, errors.New("required TLV missing")
	}

	// A hand-constructed NLRI carries only the descriptor fields; a decoded
	// one serializes every received TLV in wire order.
	tlvs := l.TLVs
	if len(tlvs) == 0 {
		tlvs = []LsTLVInterface{l.LocalNodeDesc, l.CandidatePathDesc}
	}

	buf := make([]byte, 0)
	for _, tlv := range tlvs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return l.LsNLRI.Serialize(buf)
}

func (l *LsSrPolicyCandidatePathNLRI) MarshalJSON() ([]byte, error) {
	local, err := extractLsNodeDesc(l.LocalNodeDesc, "local")
	if err != nil {
		return nil, err
	}
	cpTLV, ok := l.CandidatePathDesc.(*LsTLVSrPolicyCandidatePathDescriptor)
	if !ok {
		return nil, fmt.Errorf("invalid SR Policy candidate path descriptor type %T", l.CandidatePathDesc)
	}

	return json.Marshal(struct {
		Type          LsNLRIType                        `json:"type"`
		LocalNode     LsNodeDescriptor                  `json:"local_node_desc"`
		CandidatePath LsSrPolicyCandidatePathDescriptor `json:"candidate_path_desc"`
	}{
		Type:          l.Type(),
		LocalNode:     *local,
		CandidatePath: *cpTLV.Extract(),
	})
}

// SR Binding SID TLV (1201), RFC 9857 Section 5.1

const (
	lsSrBindingSIDFlagSRv6        uint16 = 1 << 15 // D-Flag
	lsSrBindingSIDFlagAllocated   uint16 = 1 << 14 // B-Flag
	lsSrBindingSIDFlagUnavailable uint16 = 1 << 13 // U-Flag
	lsSrBindingSIDFlagFromSRLB    uint16 = 1 << 12 // L-Flag
	lsSrBindingSIDFlagFallback    uint16 = 1 << 11 // F-Flag
)

type LsSrBindingSIDFlags struct {
	SRv6        bool `json:"srv6"`
	Allocated   bool `json:"allocated"`
	Unavailable bool `json:"unavailable"`
	FromSRLB    bool `json:"from_srlb"`
	Fallback    bool `json:"fallback"`
}

// LsSrBindingSID is the decoded SR Binding SID TLV. Label and SpecifiedLabel
// are used when Flags.SRv6 is false, SID and SpecifiedSID otherwise.
type LsSrBindingSID struct {
	Flags          LsSrBindingSIDFlags `json:"flags"`
	Label          uint32              `json:"label"`
	SpecifiedLabel uint32              `json:"specified_label"`
	SID            netip.Addr          `json:"sid,omitzero"`
	SpecifiedSID   netip.Addr          `json:"specified_sid,omitzero"`
}

type LsTLVSrBindingSID struct {
	LsTLV
	Flags          uint16
	Label          uint32
	SpecifiedLabel uint32
	SID            netip.Addr
	SpecifiedSID   netip.Addr
}

func NewLsTLVSrBindingSID(l *LsSrBindingSID) *LsTLVSrBindingSID {
	var flags uint16
	length := uint16(12)
	if l.Flags.SRv6 {
		flags |= lsSrBindingSIDFlagSRv6
		length = 36
	}
	if l.Flags.Allocated {
		flags |= lsSrBindingSIDFlagAllocated
	}
	if l.Flags.Unavailable {
		flags |= lsSrBindingSIDFlagUnavailable
	}
	if l.Flags.FromSRLB {
		flags |= lsSrBindingSIDFlagFromSRLB
	}
	if l.Flags.Fallback {
		flags |= lsSrBindingSIDFlagFallback
	}

	return &LsTLVSrBindingSID{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_BINDING_SID,
			Length: length,
		},
		Flags:          flags,
		Label:          l.Label,
		SpecifiedLabel: l.SpecifiedLabel,
		SID:            l.SID,
		SpecifiedSID:   l.SpecifiedSID,
	}
}

func (l *LsTLVSrBindingSID) Extract() *LsSrBindingSID {
	return &LsSrBindingSID{
		Flags: LsSrBindingSIDFlags{
			SRv6:        l.Flags&lsSrBindingSIDFlagSRv6 != 0,
			Allocated:   l.Flags&lsSrBindingSIDFlagAllocated != 0,
			Unavailable: l.Flags&lsSrBindingSIDFlagUnavailable != 0,
			FromSRLB:    l.Flags&lsSrBindingSIDFlagFromSRLB != 0,
			Fallback:    l.Flags&lsSrBindingSIDFlagFallback != 0,
		},
		Label:          l.Label,
		SpecifiedLabel: l.SpecifiedLabel,
		SID:            l.SID,
		SpecifiedSID:   l.SpecifiedSID,
	}
}

func (l *LsTLVSrBindingSID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_BINDING_SID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 4 {
		return malformedAttrListErr("Incorrect SR Binding SID length")
	}

	l.Flags = binary.BigEndian.Uint16(value[:2])
	// value[2:4] is reserved and ignored.

	if l.Flags&lsSrBindingSIDFlagSRv6 != 0 {
		if len(value) != 36 {
			return malformedAttrListErr("Incorrect SR Binding SID length")
		}
		l.SID = netip.AddrFrom16([16]byte(value[4:20]))
		l.SpecifiedSID = netip.AddrFrom16([16]byte(value[20:36]))
		return nil
	}

	if len(value) != 12 {
		return malformedAttrListErr("Incorrect SR Binding SID length")
	}
	l.Label = lsMplsLabelFromField(value[4:8])
	l.SpecifiedLabel = lsMplsLabelFromField(value[8:12])

	return nil
}

func (l *LsTLVSrBindingSID) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[:2], l.Flags)

	if l.Flags&lsSrBindingSIDFlagSRv6 != 0 {
		buf = append(buf, lsAddrBytes(l.SID, 16)...)
		buf = append(buf, lsAddrBytes(l.SpecifiedSID, 16)...)
	} else {
		// A decoded label is at most 20 bits; only a hand-built TLV can
		// carry one that does not fit the field.
		if l.Label > 0xfffff || l.SpecifiedLabel > 0xfffff {
			return nil, malformedAttrListErr("SR Binding SID label exceeds 20 bits")
		}
		buf = append(buf, lsMplsLabelToField(l.Label)...)
		buf = append(buf, lsMplsLabelToField(l.SpecifiedLabel)...)
	}

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrBindingSID) String() string {
	if l.Flags&lsSrBindingSIDFlagSRv6 != 0 {
		return fmt.Sprintf("{SR Binding SID: %s Specified: %s Flags: %s}", l.SID, l.SpecifiedSID, l.flagString())
	}
	return fmt.Sprintf("{SR Binding SID: %d Specified: %d Flags: %s}", l.Label, l.SpecifiedLabel, l.flagString())
}

func (l *LsTLVSrBindingSID) flagString() string {
	return lsFlagLetters(l.Flags, "DBULF")
}

func (l *LsTLVSrBindingSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrBindingSID
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrBindingSID) GetLsTLV() LsTLV {
	return l.LsTLV
}

// lsFlagLetters renders the set bits of a 16-bit flag word, MSB first, using
// one letter per bit as given in letters. Unset bits are omitted.
func lsFlagLetters(flags uint16, letters string) string {
	var b strings.Builder
	for i, r := range letters {
		if flags&(uint16(1)<<(15-i)) != 0 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// SRv6 Binding SID TLV (1212), RFC 9857 Section 5.2

const (
	lsSrv6BindingSIDFlagAllocated   uint16 = 1 << 15 // B-Flag
	lsSrv6BindingSIDFlagUnavailable uint16 = 1 << 14 // U-Flag
	lsSrv6BindingSIDFlagFallback    uint16 = 1 << 13 // F-Flag
)

type LsSrv6BindingSIDFlags struct {
	Allocated   bool `json:"allocated"`
	Unavailable bool `json:"unavailable"`
	Fallback    bool `json:"fallback"`
}

type LsSrv6BindingSID struct {
	Flags            LsSrv6BindingSIDFlags   `json:"flags"`
	SID              netip.Addr              `json:"sid"`
	SpecifiedSID     netip.Addr              `json:"specified_sid"`
	EndpointBehavior *LsSrv6EndpointBehavior `json:"endpoint_behavior,omitempty"`
	SIDStructure     *LsSrv6SIDStructure     `json:"sid_structure,omitempty"`
}

type LsTLVSrv6BindingSID struct {
	LsTLV
	Flags        uint16
	SID          netip.Addr
	SpecifiedSID netip.Addr
	SubTLVs      []LsTLVInterface
}

const lsSrv6BindingSIDFixedLen = 36

func NewLsTLVSrv6BindingSID(l *LsSrv6BindingSID) *LsTLVSrv6BindingSID {
	var flags uint16
	if l.Flags.Allocated {
		flags |= lsSrv6BindingSIDFlagAllocated
	}
	if l.Flags.Unavailable {
		flags |= lsSrv6BindingSIDFlagUnavailable
	}
	if l.Flags.Fallback {
		flags |= lsSrv6BindingSIDFlagFallback
	}

	subTLVs := lsSrv6SubTLVsFromModel(l.EndpointBehavior, l.SIDStructure)

	return &LsTLVSrv6BindingSID{
		LsTLV: LsTLV{
			Type:   LS_TLV_SRV6_BINDING_SID,
			Length: uint16(lsSrv6BindingSIDFixedLen + lsSubTLVsLen(subTLVs)),
		},
		Flags:        flags,
		SID:          l.SID,
		SpecifiedSID: l.SpecifiedSID,
		SubTLVs:      subTLVs,
	}
}

func (l *LsTLVSrv6BindingSID) Extract() *LsSrv6BindingSID {
	eb, ss := lsSrv6SubTLVsToModel(l.SubTLVs)
	return &LsSrv6BindingSID{
		Flags: LsSrv6BindingSIDFlags{
			Allocated:   l.Flags&lsSrv6BindingSIDFlagAllocated != 0,
			Unavailable: l.Flags&lsSrv6BindingSIDFlagUnavailable != 0,
			Fallback:    l.Flags&lsSrv6BindingSIDFlagFallback != 0,
		},
		SID:              l.SID,
		SpecifiedSID:     l.SpecifiedSID,
		EndpointBehavior: eb,
		SIDStructure:     ss,
	}
}

func (l *LsTLVSrv6BindingSID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SRV6_BINDING_SID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < lsSrv6BindingSIDFixedLen {
		return malformedAttrListErr("Incorrect SRv6 Binding SID length")
	}

	l.Flags = binary.BigEndian.Uint16(value[:2])
	// value[2:4] is reserved and ignored.
	l.SID = netip.AddrFrom16([16]byte(value[4:20]))
	l.SpecifiedSID = netip.AddrFrom16([16]byte(value[20:36]))

	l.SubTLVs, err = lsWalkSubTLVs(value[lsSrv6BindingSIDFixedLen:], lsSrv6SubTLVAlloc)
	return err
}

func (l *LsTLVSrv6BindingSID) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[:2], l.Flags)
	buf = append(buf, lsAddrBytes(l.SID, 16)...)
	buf = append(buf, lsAddrBytes(l.SpecifiedSID, 16)...)

	sub, err := lsSerializeSubTLVs(l.SubTLVs)
	if err != nil {
		return nil, err
	}
	buf = append(buf, sub...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrv6BindingSID) String() string {
	return fmt.Sprintf("{SRv6 Binding SID: %s Specified: %s Flags: %s}", l.SID, l.SpecifiedSID, lsFlagLetters(l.Flags, "BUF"))
}

func (l *LsTLVSrv6BindingSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrv6BindingSID
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrv6BindingSID) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Candidate Path State TLV (1202), RFC 9857 Section 5.3

const (
	lsSrCPStateFlagShutdown        uint16 = 1 << 15 // S-Flag
	lsSrCPStateFlagActive          uint16 = 1 << 14 // A-Flag
	lsSrCPStateFlagBackup          uint16 = 1 << 13 // B-Flag
	lsSrCPStateFlagEvaluated       uint16 = 1 << 12 // E-Flag
	lsSrCPStateFlagValidSIDList    uint16 = 1 << 11 // V-Flag
	lsSrCPStateFlagOnDemand        uint16 = 1 << 10 // O-Flag
	lsSrCPStateFlagDelegated       uint16 = 1 << 9  // D-Flag
	lsSrCPStateFlagProvisioned     uint16 = 1 << 8  // C-Flag
	lsSrCPStateFlagDropUponInvalid uint16 = 1 << 7  // I-Flag
	lsSrCPStateFlagTransitEligible uint16 = 1 << 6  // T-Flag
	lsSrCPStateFlagDropping        uint16 = 1 << 5  // U-Flag
)

type LsSrCandidatePathStateFlags struct {
	Shutdown        bool `json:"shutdown"`
	Active          bool `json:"active"`
	Backup          bool `json:"backup"`
	Evaluated       bool `json:"evaluated"`
	ValidSIDList    bool `json:"valid_sid_list"`
	OnDemand        bool `json:"on_demand"`
	Delegated       bool `json:"delegated"`
	Provisioned     bool `json:"provisioned"`
	DropUponInvalid bool `json:"drop_upon_invalid"`
	TransitEligible bool `json:"transit_eligible"`
	Dropping        bool `json:"dropping"`
}

type LsSrCandidatePathState struct {
	Priority   uint8                       `json:"priority"`
	Flags      LsSrCandidatePathStateFlags `json:"flags"`
	Preference uint32                      `json:"preference"`
}

type LsTLVSrCandidatePathState struct {
	LsTLV
	Priority   uint8
	Flags      uint16
	Preference uint32
}

func NewLsTLVSrCandidatePathState(l *LsSrCandidatePathState) *LsTLVSrCandidatePathState {
	var flags uint16
	set := func(on bool, bit uint16) {
		if on {
			flags |= bit
		}
	}
	set(l.Flags.Shutdown, lsSrCPStateFlagShutdown)
	set(l.Flags.Active, lsSrCPStateFlagActive)
	set(l.Flags.Backup, lsSrCPStateFlagBackup)
	set(l.Flags.Evaluated, lsSrCPStateFlagEvaluated)
	set(l.Flags.ValidSIDList, lsSrCPStateFlagValidSIDList)
	set(l.Flags.OnDemand, lsSrCPStateFlagOnDemand)
	set(l.Flags.Delegated, lsSrCPStateFlagDelegated)
	set(l.Flags.Provisioned, lsSrCPStateFlagProvisioned)
	set(l.Flags.DropUponInvalid, lsSrCPStateFlagDropUponInvalid)
	set(l.Flags.TransitEligible, lsSrCPStateFlagTransitEligible)
	set(l.Flags.Dropping, lsSrCPStateFlagDropping)

	return &LsTLVSrCandidatePathState{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_CP_STATE,
			Length: 8,
		},
		Priority:   l.Priority,
		Flags:      flags,
		Preference: l.Preference,
	}
}

func (l *LsTLVSrCandidatePathState) Extract() *LsSrCandidatePathState {
	return &LsSrCandidatePathState{
		Priority: l.Priority,
		Flags: LsSrCandidatePathStateFlags{
			Shutdown:        l.Flags&lsSrCPStateFlagShutdown != 0,
			Active:          l.Flags&lsSrCPStateFlagActive != 0,
			Backup:          l.Flags&lsSrCPStateFlagBackup != 0,
			Evaluated:       l.Flags&lsSrCPStateFlagEvaluated != 0,
			ValidSIDList:    l.Flags&lsSrCPStateFlagValidSIDList != 0,
			OnDemand:        l.Flags&lsSrCPStateFlagOnDemand != 0,
			Delegated:       l.Flags&lsSrCPStateFlagDelegated != 0,
			Provisioned:     l.Flags&lsSrCPStateFlagProvisioned != 0,
			DropUponInvalid: l.Flags&lsSrCPStateFlagDropUponInvalid != 0,
			TransitEligible: l.Flags&lsSrCPStateFlagTransitEligible != 0,
			Dropping:        l.Flags&lsSrCPStateFlagDropping != 0,
		},
		Preference: l.Preference,
	}
}

func (l *LsTLVSrCandidatePathState) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_CP_STATE {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) != 8 {
		return malformedAttrListErr("Incorrect SR Candidate Path State length")
	}

	l.Priority = value[0]
	// value[1] is reserved and ignored.
	l.Flags = binary.BigEndian.Uint16(value[2:4])
	l.Preference = binary.BigEndian.Uint32(value[4:8])

	return nil
}

func (l *LsTLVSrCandidatePathState) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = l.Priority
	binary.BigEndian.PutUint16(buf[2:4], l.Flags)
	binary.BigEndian.PutUint32(buf[4:8], l.Preference)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrCandidatePathState) String() string {
	return fmt.Sprintf("{SR CP State: Priority:%d Preference:%d Flags:%s}", l.Priority, l.Preference, lsFlagLetters(l.Flags, "SABEVODCITU"))
}

func (l *LsTLVSrCandidatePathState) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrCandidatePathState
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrCandidatePathState) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Candidate Path Name TLV (1203) and SR Policy Name TLV (1213),
// RFC 9857 Sections 5.5 and 5.4

type LsTLVSrCandidatePathName struct {
	LsTLV
	Name string
}

func NewLsTLVSrCandidatePathName(name *string) *LsTLVSrCandidatePathName {
	return &LsTLVSrCandidatePathName{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_CP_NAME,
			Length: uint16(len(*name)),
		},
		Name: *name,
	}
}

func (l *LsTLVSrCandidatePathName) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_CP_NAME {
		return malformedAttrListErr("Unexpected TLV type")
	}

	l.Name = string(value)
	return nil
}

func (l *LsTLVSrCandidatePathName) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize([]byte(l.Name))
}

func (l *LsTLVSrCandidatePathName) String() string {
	return fmt.Sprintf("{SR CP Name: %s}", l.Name)
}

func (l *LsTLVSrCandidatePathName) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Name string    `json:"candidate_path_name"`
	}{
		l.Type,
		l.Name,
	})
}

func (l *LsTLVSrCandidatePathName) GetLsTLV() LsTLV {
	return l.LsTLV
}

type LsTLVSrPolicyName struct {
	LsTLV
	Name string
}

func NewLsTLVSrPolicyName(name *string) *LsTLVSrPolicyName {
	return &LsTLVSrPolicyName{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_POLICY_NAME,
			Length: uint16(len(*name)),
		},
		Name: *name,
	}
}

func (l *LsTLVSrPolicyName) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_POLICY_NAME {
		return malformedAttrListErr("Unexpected TLV type")
	}

	l.Name = string(value)
	return nil
}

func (l *LsTLVSrPolicyName) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize([]byte(l.Name))
}

func (l *LsTLVSrPolicyName) String() string {
	return fmt.Sprintf("{SR Policy Name: %s}", l.Name)
}

func (l *LsTLVSrPolicyName) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Name string    `json:"policy_name"`
	}{
		l.Type,
		l.Name,
	})
}

func (l *LsTLVSrPolicyName) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Segment List Metric sub-TLV (1207), RFC 9857 Section 5.7.2

const (
	lsSrSegmentListMetricFlagMargin   uint8 = 1 << 7 // M-Flag
	lsSrSegmentListMetricFlagAbsolute uint8 = 1 << 6 // A-Flag
	lsSrSegmentListMetricFlagBound    uint8 = 1 << 5 // B-Flag
	lsSrSegmentListMetricFlagValue    uint8 = 1 << 4 // V-Flag
)

type LsSrSegmentListMetricFlags struct {
	Margin   bool `json:"margin"`
	Absolute bool `json:"absolute"`
	Bound    bool `json:"bound"`
	Value    bool `json:"value"`
}

type LsSrSegmentListMetric struct {
	MetricType uint8                      `json:"metric_type"`
	Flags      LsSrSegmentListMetricFlags `json:"flags"`
	Margin     uint32                     `json:"margin"`
	Bound      uint32                     `json:"bound"`
	Value      uint32                     `json:"value"`
}

type LsTLVSrSegmentListMetric struct {
	LsTLV
	MetricType uint8
	Flags      uint8
	Margin     uint32
	Bound      uint32
	Value      uint32
}

func NewLsTLVSrSegmentListMetric(l *LsSrSegmentListMetric) *LsTLVSrSegmentListMetric {
	var flags uint8
	if l.Flags.Margin {
		flags |= lsSrSegmentListMetricFlagMargin
	}
	if l.Flags.Absolute {
		flags |= lsSrSegmentListMetricFlagAbsolute
	}
	if l.Flags.Bound {
		flags |= lsSrSegmentListMetricFlagBound
	}
	if l.Flags.Value {
		flags |= lsSrSegmentListMetricFlagValue
	}

	return &LsTLVSrSegmentListMetric{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_SEGMENT_LIST_METRIC,
			Length: 16,
		},
		MetricType: l.MetricType,
		Flags:      flags,
		Margin:     l.Margin,
		Bound:      l.Bound,
		Value:      l.Value,
	}
}

func (l *LsTLVSrSegmentListMetric) Extract() *LsSrSegmentListMetric {
	return &LsSrSegmentListMetric{
		MetricType: l.MetricType,
		Flags: LsSrSegmentListMetricFlags{
			Margin:   l.Flags&lsSrSegmentListMetricFlagMargin != 0,
			Absolute: l.Flags&lsSrSegmentListMetricFlagAbsolute != 0,
			Bound:    l.Flags&lsSrSegmentListMetricFlagBound != 0,
			Value:    l.Flags&lsSrSegmentListMetricFlagValue != 0,
		},
		Margin: l.Margin,
		Bound:  l.Bound,
		Value:  l.Value,
	}
}

func (l *LsTLVSrSegmentListMetric) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_SEGMENT_LIST_METRIC {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) != 16 {
		return malformedAttrListErr("Incorrect SR Segment List Metric length")
	}

	l.MetricType = value[0]
	l.Flags = value[1]
	// value[2:4] is reserved and ignored.
	l.Margin = binary.BigEndian.Uint32(value[4:8])
	l.Bound = binary.BigEndian.Uint32(value[8:12])
	l.Value = binary.BigEndian.Uint32(value[12:16])

	return nil
}

func (l *LsTLVSrSegmentListMetric) Serialize() ([]byte, error) {
	buf := make([]byte, 16)
	buf[0] = l.MetricType
	buf[1] = l.Flags
	binary.BigEndian.PutUint32(buf[4:8], l.Margin)
	binary.BigEndian.PutUint32(buf[8:12], l.Bound)
	binary.BigEndian.PutUint32(buf[12:16], l.Value)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrSegmentListMetric) String() string {
	return fmt.Sprintf("{Metric: Type:%d Margin:%d Bound:%d Value:%d Flags:%s}",
		l.MetricType, l.Margin, l.Bound, l.Value, lsFlagLetters(uint16(l.Flags)<<8, "MABV"))
}

func (l *LsTLVSrSegmentListMetric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrSegmentListMetric
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrSegmentListMetric) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Segment List Bandwidth sub-TLV (1216), RFC 9857 Section 5.7.3

type LsTLVSrSegmentListBandwidth struct {
	LsTLV
	Bandwidth float32
}

func NewLsTLVSrSegmentListBandwidth(bw *float32) *LsTLVSrSegmentListBandwidth {
	return &LsTLVSrSegmentListBandwidth{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_SEGMENT_LIST_BANDWIDTH,
			Length: 4,
		},
		Bandwidth: *bw,
	}
}

func (l *LsTLVSrSegmentListBandwidth) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_SEGMENT_LIST_BANDWIDTH {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) != 4 {
		return malformedAttrListErr("Incorrect SR Segment List Bandwidth length")
	}

	// The value is not checked: RFC 9552 section 8.2.2 forbids treating
	// the attribute as malformed based on TLV contents. lsValidBandwidth
	// keeps a nonsensical value out of the model instead.
	l.Bandwidth = math.Float32frombits(binary.BigEndian.Uint32(value))

	return nil
}

func (l *LsTLVSrSegmentListBandwidth) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, math.Float32bits(l.Bandwidth))

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrSegmentListBandwidth) String() string {
	return fmt.Sprintf("{Bandwidth: %v}", l.Bandwidth)
}

func (l *LsTLVSrSegmentListBandwidth) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsTLVType `json:"type"`
		Bandwidth float32   `json:"bandwidth"`
	}{
		l.Type,
		l.Bandwidth,
	})
}

func (l *LsTLVSrSegmentListBandwidth) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Segment List Identifier sub-TLV (1217), RFC 9857 Section 5.7.4

type LsTLVSrSegmentListIdentifier struct {
	LsTLV
	Identifier uint32
}

func NewLsTLVSrSegmentListIdentifier(id *uint32) *LsTLVSrSegmentListIdentifier {
	return &LsTLVSrSegmentListIdentifier{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_SEGMENT_LIST_IDENTIFIER,
			Length: 4,
		},
		Identifier: *id,
	}
}

func (l *LsTLVSrSegmentListIdentifier) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_SEGMENT_LIST_IDENTIFIER {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) != 4 {
		return malformedAttrListErr("Incorrect SR Segment List Identifier length")
	}

	l.Identifier = binary.BigEndian.Uint32(value)
	return nil
}

func (l *LsTLVSrSegmentListIdentifier) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, l.Identifier)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrSegmentListIdentifier) String() string {
	return fmt.Sprintf("{Identifier: %d}", l.Identifier)
}

func (l *LsTLVSrSegmentListIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type       LsTLVType `json:"type"`
		Identifier uint32    `json:"identifier"`
	}{
		l.Type,
		l.Identifier,
	})
}

func (l *LsTLVSrSegmentListIdentifier) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Segment sub-TLV (1206), RFC 9857 Section 5.7.1

// LsSrSegmentType is the Segment Type of an SR Segment sub-TLV, see the
// "SR Segment Types" table in RFC 9857 Section 5.7.1 (letters follow RFC 9256).
type LsSrSegmentType uint8

const (
	LS_SR_SEGMENT_TYPE_UNKNOWN LsSrSegmentType = iota
	LS_SR_SEGMENT_TYPE_A_MPLS_LABEL
	LS_SR_SEGMENT_TYPE_B_SRV6_SID
	LS_SR_SEGMENT_TYPE_C_IPV4_NODE
	LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS
	LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE
	LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY
	LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS
	LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS
	LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6
	LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6
	LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6
)

func (t LsSrSegmentType) String() string {
	switch t {
	case LS_SR_SEGMENT_TYPE_A_MPLS_LABEL:
		return "A"
	case LS_SR_SEGMENT_TYPE_B_SRV6_SID:
		return "B"
	case LS_SR_SEGMENT_TYPE_C_IPV4_NODE:
		return "C"
	case LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS:
		return "D"
	case LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE:
		return "E"
	case LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		return "F"
	case LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS:
		return "G"
	case LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS:
		return "H"
	case LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6:
		return "I"
	case LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6:
		return "J"
	case LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		return "K"
	default:
		return fmt.Sprintf("LsSrSegmentType(%d)", uint8(t))
	}
}

// IsSRv6 reports whether the segment's SID field carries a 16-octet SRv6 SID
// (true) or a 4-octet SR-MPLS label field (false).
func (t LsSrSegmentType) IsSRv6() bool {
	switch t {
	case LS_SR_SEGMENT_TYPE_B_SRV6_SID,
		LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6,
		LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6,
		LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		return true
	}
	return false
}

// lsSrSegmentSIDLen returns the size of the SID field for a segment type and
// whether the type is known.
func lsSrSegmentSIDLen(t LsSrSegmentType) (int, bool) {
	if t == LS_SR_SEGMENT_TYPE_UNKNOWN || t > LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6 {
		return 0, false
	}
	if t.IsSRv6() {
		return 16, true
	}
	return 4, true
}

// lsSrSegmentDescLen returns the size of the Segment Descriptor that follows
// the SID field for a known segment type.
func lsSrSegmentDescLen(t LsSrSegmentType) int {
	switch t {
	case LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, LS_SR_SEGMENT_TYPE_B_SRV6_SID:
		return 1
	case LS_SR_SEGMENT_TYPE_C_IPV4_NODE:
		return 1 + 4
	case LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS, LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6:
		return 1 + 16
	case LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE, LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		return 4 + 4
	case LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6:
		return 16 + 4 + 16 + 4
	case LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS, LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		return 16 + 16
	}
	return 0
}

const (
	lsSrSegmentFlagSIDPresent     uint16 = 1 << 15 // S-Flag
	lsSrSegmentFlagExplicit       uint16 = 1 << 14 // E-Flag
	lsSrSegmentFlagVerified       uint16 = 1 << 13 // V-Flag
	lsSrSegmentFlagResolved       uint16 = 1 << 12 // R-Flag
	lsSrSegmentFlagAlgorithmValid uint16 = 1 << 11 // A-Flag
)

type LsSrSegmentFlags struct {
	SIDPresent     bool `json:"sid_present"`
	Explicit       bool `json:"explicit"`
	Verified       bool `json:"verified"`
	Resolved       bool `json:"resolved"`
	AlgorithmValid bool `json:"algorithm_valid"`
}

// LsSrSegment is the decoded SR Segment sub-TLV. Which fields are meaningful
// depends on SegmentType:
//   - Label: SR-MPLS types (A, C, D, E, F, G, H); SID: SRv6 types (B, I, J, K)
//   - Algorithm: A, B, C, D, I
//   - LocalAddress: node address for C, D, E, I; local address for F, G, H, J, K
//   - RemoteAddress: F, G, H, J, K
//   - LocalInterfaceID: E, G, J; RemoteInterfaceID: G, J
type LsSrSegment struct {
	SegmentType       LsSrSegmentType         `json:"segment_type"`
	Flags             LsSrSegmentFlags        `json:"flags"`
	Label             uint32                  `json:"label,omitempty"`
	SID               netip.Addr              `json:"sid,omitzero"`
	Algorithm         uint8                   `json:"algorithm"`
	LocalAddress      netip.Addr              `json:"local_address,omitzero"`
	RemoteAddress     netip.Addr              `json:"remote_address,omitzero"`
	LocalInterfaceID  uint32                  `json:"local_interface_id,omitempty"`
	RemoteInterfaceID uint32                  `json:"remote_interface_id,omitempty"`
	EndpointBehavior  *LsSrv6EndpointBehavior `json:"endpoint_behavior,omitempty"`
	SIDStructure      *LsSrv6SIDStructure     `json:"sid_structure,omitempty"`
}

type LsTLVSrSegment struct {
	LsTLV
	SegmentType       LsSrSegmentType
	Flags             uint16
	Label             uint32
	SID               netip.Addr
	Algorithm         uint8
	LocalAddress      netip.Addr
	RemoteAddress     netip.Addr
	LocalInterfaceID  uint32
	RemoteInterfaceID uint32
	SubTLVs           []LsTLVInterface
}

func NewLsTLVSrSegment(l *LsSrSegment) *LsTLVSrSegment {
	var flags uint16
	if l.Flags.SIDPresent {
		flags |= lsSrSegmentFlagSIDPresent
	}
	if l.Flags.Explicit {
		flags |= lsSrSegmentFlagExplicit
	}
	if l.Flags.Verified {
		flags |= lsSrSegmentFlagVerified
	}
	if l.Flags.Resolved {
		flags |= lsSrSegmentFlagResolved
	}
	if l.Flags.AlgorithmValid {
		flags |= lsSrSegmentFlagAlgorithmValid
	}

	subTLVs := lsSrv6SubTLVsFromModel(l.EndpointBehavior, l.SIDStructure)
	sidLen, _ := lsSrSegmentSIDLen(l.SegmentType)

	return &LsTLVSrSegment{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_SEGMENT,
			Length: uint16(4 + sidLen + lsSrSegmentDescLen(l.SegmentType) + lsSubTLVsLen(subTLVs)),
		},
		SegmentType:       l.SegmentType,
		Flags:             flags,
		Label:             l.Label,
		SID:               l.SID,
		Algorithm:         l.Algorithm,
		LocalAddress:      l.LocalAddress,
		RemoteAddress:     l.RemoteAddress,
		LocalInterfaceID:  l.LocalInterfaceID,
		RemoteInterfaceID: l.RemoteInterfaceID,
		SubTLVs:           subTLVs,
	}
}

func (l *LsTLVSrSegment) Extract() *LsSrSegment {
	eb, ss := lsSrv6SubTLVsToModel(l.SubTLVs)
	s := &LsSrSegment{
		SegmentType: l.SegmentType,
		Flags: LsSrSegmentFlags{
			SIDPresent:     l.Flags&lsSrSegmentFlagSIDPresent != 0,
			Explicit:       l.Flags&lsSrSegmentFlagExplicit != 0,
			Verified:       l.Flags&lsSrSegmentFlagVerified != 0,
			Resolved:       l.Flags&lsSrSegmentFlagResolved != 0,
			AlgorithmValid: l.Flags&lsSrSegmentFlagAlgorithmValid != 0,
		},
		Algorithm:         l.Algorithm,
		LocalAddress:      l.LocalAddress,
		RemoteAddress:     l.RemoteAddress,
		LocalInterfaceID:  l.LocalInterfaceID,
		RemoteInterfaceID: l.RemoteInterfaceID,
		EndpointBehavior:  eb,
		SIDStructure:      ss,
	}
	// The SID field is always present on the wire but only carries a value
	// when the S-Flag is set.
	if s.Flags.SIDPresent {
		s.Label = l.Label
		s.SID = l.SID
	}
	return s
}

func (l *LsTLVSrSegment) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_SEGMENT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 4 {
		return malformedAttrListErr("Incorrect SR Segment length")
	}

	l.SegmentType = LsSrSegmentType(value[0])
	// value[1] is reserved and ignored.
	l.Flags = binary.BigEndian.Uint16(value[2:4])

	sidLen, ok := lsSrSegmentSIDLen(l.SegmentType)
	if !ok {
		return fmt.Errorf("%w: SR Segment Type %d", errLsSkipTLV, uint8(l.SegmentType))
	}
	descLen := lsSrSegmentDescLen(l.SegmentType)

	if len(value) < 4+sidLen+descLen {
		return malformedAttrListErr("Incorrect SR Segment length")
	}

	p := 4
	if sidLen == 16 {
		l.SID = netip.AddrFrom16([16]byte(value[p : p+16]))
	} else {
		l.Label = lsMplsLabelFromField(value[p : p+4])
	}
	p += sidLen

	desc := value[p : p+descLen]
	switch l.SegmentType {
	case LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, LS_SR_SEGMENT_TYPE_B_SRV6_SID:
		l.Algorithm = desc[0]
	case LS_SR_SEGMENT_TYPE_C_IPV4_NODE:
		l.Algorithm = desc[0]
		l.LocalAddress = netip.AddrFrom4([4]byte(desc[1:5]))
	case LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS, LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6:
		l.Algorithm = desc[0]
		l.LocalAddress = netip.AddrFrom16([16]byte(desc[1:17]))
	case LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE:
		l.LocalAddress = netip.AddrFrom4([4]byte(desc[:4]))
		l.LocalInterfaceID = binary.BigEndian.Uint32(desc[4:8])
	case LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		l.LocalAddress = netip.AddrFrom4([4]byte(desc[:4]))
		l.RemoteAddress = netip.AddrFrom4([4]byte(desc[4:8]))
	case LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6:
		l.LocalAddress = netip.AddrFrom16([16]byte(desc[:16]))
		l.LocalInterfaceID = binary.BigEndian.Uint32(desc[16:20])
		l.RemoteAddress = netip.AddrFrom16([16]byte(desc[20:36]))
		l.RemoteInterfaceID = binary.BigEndian.Uint32(desc[36:40])
	case LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS, LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		l.LocalAddress = netip.AddrFrom16([16]byte(desc[:16]))
		l.RemoteAddress = netip.AddrFrom16([16]byte(desc[16:32]))
	}
	p += descLen

	l.SubTLVs, err = lsWalkSubTLVs(value[p:], lsSrv6SubTLVAlloc)
	return err
}

func (l *LsTLVSrSegment) Serialize() ([]byte, error) {
	sidLen, ok := lsSrSegmentSIDLen(l.SegmentType)
	if !ok {
		return nil, malformedAttrListErr("Unknown SR Segment Type")
	}

	// Refuse only what the wire format cannot carry: a label wider than
	// its 20-bit field and an address that does not fit an IPv4
	// descriptor slot. Any decoded segment passes, so a received
	// attribute always re-serializes; LsSrSegment.Validate covers the
	// semantic checks when a segment is built through the API.
	if sidLen == 4 && l.Label > 0xfffff {
		return nil, malformedAttrListErr("SR segment label exceeds 20 bits")
	}
	fits4 := func(addr netip.Addr) bool {
		return !addr.IsValid() || addr.Unmap().Is4()
	}
	switch l.SegmentType {
	case LS_SR_SEGMENT_TYPE_C_IPV4_NODE, LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE, LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		if !fits4(l.LocalAddress) || !fits4(l.RemoteAddress) {
			return nil, malformedAttrListErr("SR segment address does not fit an IPv4 descriptor")
		}
	}

	buf := make([]byte, 4)
	buf[0] = uint8(l.SegmentType)
	binary.BigEndian.PutUint16(buf[2:4], l.Flags)

	if sidLen == 16 {
		buf = append(buf, lsAddrBytes(l.SID, 16)...)
	} else {
		buf = append(buf, lsMplsLabelToField(l.Label)...)
	}

	switch l.SegmentType {
	case LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, LS_SR_SEGMENT_TYPE_B_SRV6_SID:
		buf = append(buf, l.Algorithm)
	case LS_SR_SEGMENT_TYPE_C_IPV4_NODE:
		buf = append(buf, l.Algorithm)
		buf = append(buf, lsAddrBytes(l.LocalAddress, 4)...)
	case LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS, LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6:
		buf = append(buf, l.Algorithm)
		buf = append(buf, lsAddrBytes(l.LocalAddress, 16)...)
	case LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE:
		buf = append(buf, lsAddrBytes(l.LocalAddress, 4)...)
		buf = binary.BigEndian.AppendUint32(buf, l.LocalInterfaceID)
	case LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		buf = append(buf, lsAddrBytes(l.LocalAddress, 4)...)
		buf = append(buf, lsAddrBytes(l.RemoteAddress, 4)...)
	case LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6:
		buf = append(buf, lsAddrBytes(l.LocalAddress, 16)...)
		buf = binary.BigEndian.AppendUint32(buf, l.LocalInterfaceID)
		buf = append(buf, lsAddrBytes(l.RemoteAddress, 16)...)
		buf = binary.BigEndian.AppendUint32(buf, l.RemoteInterfaceID)
	case LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS, LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		buf = append(buf, lsAddrBytes(l.LocalAddress, 16)...)
		buf = append(buf, lsAddrBytes(l.RemoteAddress, 16)...)
	}

	sub, err := lsSerializeSubTLVs(l.SubTLVs)
	if err != nil {
		return nil, err
	}
	buf = append(buf, sub...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrSegment) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "{Segment: Type:%s", l.SegmentType)
	if l.SegmentType.IsSRv6() {
		fmt.Fprintf(&b, " SID:%s", l.SID)
	} else {
		fmt.Fprintf(&b, " Label:%d", l.Label)
	}
	switch l.SegmentType {
	case LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, LS_SR_SEGMENT_TYPE_B_SRV6_SID:
		fmt.Fprintf(&b, " Algo:%d", l.Algorithm)
	case LS_SR_SEGMENT_TYPE_C_IPV4_NODE, LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS, LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6:
		fmt.Fprintf(&b, " Node:%s Algo:%d", l.LocalAddress, l.Algorithm)
	case LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE:
		fmt.Fprintf(&b, " Node:%s IfID:%d", l.LocalAddress, l.LocalInterfaceID)
	case LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY, LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS, LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		fmt.Fprintf(&b, " Local:%s Remote:%s", l.LocalAddress, l.RemoteAddress)
	case LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6:
		fmt.Fprintf(&b, " Local:%s/%d Remote:%s/%d", l.LocalAddress, l.LocalInterfaceID, l.RemoteAddress, l.RemoteInterfaceID)
	}
	fmt.Fprintf(&b, " Flags:%s}", lsFlagLetters(l.Flags, "SEVRA"))
	return b.String()
}

func (l *LsTLVSrSegment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrSegment
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrSegment) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Segment List TLV (1205), RFC 9857 Section 5.7

const (
	lsSrSegmentListFlagSRv6           uint16 = 1 << 15 // D-Flag
	lsSrSegmentListFlagExplicit       uint16 = 1 << 14 // E-Flag
	lsSrSegmentListFlagComputed       uint16 = 1 << 13 // C-Flag
	lsSrSegmentListFlagVerified       uint16 = 1 << 12 // V-Flag
	lsSrSegmentListFlagResolved       uint16 = 1 << 11 // R-Flag
	lsSrSegmentListFlagFailed         uint16 = 1 << 10 // F-Flag
	lsSrSegmentListFlagAllAlgorithm   uint16 = 1 << 9  // A-Flag
	lsSrSegmentListFlagAllTopology    uint16 = 1 << 8  // T-Flag
	lsSrSegmentListFlagRemovedByFault uint16 = 1 << 7  // M-Flag
)

type LsSrSegmentListFlags struct {
	SRv6           bool `json:"srv6"`
	Explicit       bool `json:"explicit"`
	Computed       bool `json:"computed"`
	Verified       bool `json:"verified"`
	Resolved       bool `json:"resolved"`
	Failed         bool `json:"failed"`
	AllAlgorithm   bool `json:"all_algorithm"`
	AllTopology    bool `json:"all_topology"`
	RemovedByFault bool `json:"removed_by_fault"`
}

type LsSrSegmentList struct {
	Flags      LsSrSegmentListFlags    `json:"flags"`
	MTID       uint16                  `json:"mtid"`
	Algorithm  uint8                   `json:"algorithm"`
	Weight     uint32                  `json:"weight"`
	Segments   []LsSrSegment           `json:"segments"`
	Metrics    []LsSrSegmentListMetric `json:"metrics,omitempty"`
	Bandwidth  *float32                `json:"bandwidth,omitempty"`
	Identifier *uint32                 `json:"identifier,omitempty"`
}

type LsTLVSrSegmentList struct {
	LsTLV
	Flags     uint16
	MTID      uint16
	Algorithm uint8
	Weight    uint32
	SubTLVs   []LsTLVInterface
}

const lsSrSegmentListFixedLen = 12

func NewLsTLVSrSegmentList(l *LsSrSegmentList) *LsTLVSrSegmentList {
	var flags uint16
	set := func(on bool, bit uint16) {
		if on {
			flags |= bit
		}
	}
	set(l.Flags.SRv6, lsSrSegmentListFlagSRv6)
	set(l.Flags.Explicit, lsSrSegmentListFlagExplicit)
	set(l.Flags.Computed, lsSrSegmentListFlagComputed)
	set(l.Flags.Verified, lsSrSegmentListFlagVerified)
	set(l.Flags.Resolved, lsSrSegmentListFlagResolved)
	set(l.Flags.Failed, lsSrSegmentListFlagFailed)
	set(l.Flags.AllAlgorithm, lsSrSegmentListFlagAllAlgorithm)
	set(l.Flags.AllTopology, lsSrSegmentListFlagAllTopology)
	set(l.Flags.RemovedByFault, lsSrSegmentListFlagRemovedByFault)

	subTLVs := []LsTLVInterface{}
	for i := range l.Segments {
		subTLVs = append(subTLVs, NewLsTLVSrSegment(&l.Segments[i]))
	}
	for i := range l.Metrics {
		subTLVs = append(subTLVs, NewLsTLVSrSegmentListMetric(&l.Metrics[i]))
	}
	if l.Bandwidth != nil {
		subTLVs = append(subTLVs, NewLsTLVSrSegmentListBandwidth(l.Bandwidth))
	}
	if l.Identifier != nil {
		subTLVs = append(subTLVs, NewLsTLVSrSegmentListIdentifier(l.Identifier))
	}

	return &LsTLVSrSegmentList{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_SEGMENT_LIST,
			Length: uint16(lsSrSegmentListFixedLen + lsSubTLVsLen(subTLVs)),
		},
		Flags:     flags,
		MTID:      l.MTID,
		Algorithm: l.Algorithm,
		Weight:    l.Weight,
		SubTLVs:   subTLVs,
	}
}

func (l *LsTLVSrSegmentList) Extract() *LsSrSegmentList {
	sl := &LsSrSegmentList{
		Flags: LsSrSegmentListFlags{
			SRv6:           l.Flags&lsSrSegmentListFlagSRv6 != 0,
			Explicit:       l.Flags&lsSrSegmentListFlagExplicit != 0,
			Computed:       l.Flags&lsSrSegmentListFlagComputed != 0,
			Verified:       l.Flags&lsSrSegmentListFlagVerified != 0,
			Resolved:       l.Flags&lsSrSegmentListFlagResolved != 0,
			Failed:         l.Flags&lsSrSegmentListFlagFailed != 0,
			AllAlgorithm:   l.Flags&lsSrSegmentListFlagAllAlgorithm != 0,
			AllTopology:    l.Flags&lsSrSegmentListFlagAllTopology != 0,
			RemovedByFault: l.Flags&lsSrSegmentListFlagRemovedByFault != 0,
		},
		MTID:      l.MTID,
		Algorithm: l.Algorithm,
		Weight:    l.Weight,
		Segments:  []LsSrSegment{},
	}

	for _, sub := range l.SubTLVs {
		switch v := sub.(type) {
		case *LsTLVSrSegment:
			sl.Segments = append(sl.Segments, *v.Extract())
		case *LsTLVSrSegmentListMetric:
			sl.Metrics = append(sl.Metrics, *v.Extract())
		case *LsTLVSrSegmentListBandwidth:
			if sl.Bandwidth == nil && lsValidBandwidth(v.Bandwidth) {
				bw := v.Bandwidth
				sl.Bandwidth = &bw
			}
		case *LsTLVSrSegmentListIdentifier:
			if sl.Identifier == nil {
				id := v.Identifier
				sl.Identifier = &id
			}
		}
	}

	return sl
}

func lsSrSegmentListSubTLVAlloc(t LsTLVType) LsTLVInterface {
	switch t {
	case LS_TLV_SR_SEGMENT:
		return &LsTLVSrSegment{}
	case LS_TLV_SR_SEGMENT_LIST_METRIC:
		return &LsTLVSrSegmentListMetric{}
	case LS_TLV_SR_SEGMENT_LIST_BANDWIDTH:
		return &LsTLVSrSegmentListBandwidth{}
	case LS_TLV_SR_SEGMENT_LIST_IDENTIFIER:
		return &LsTLVSrSegmentListIdentifier{}
	}
	return nil
}

func (l *LsTLVSrSegmentList) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_SEGMENT_LIST {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < lsSrSegmentListFixedLen {
		return malformedAttrListErr("Incorrect SR Segment List length")
	}

	l.Flags = binary.BigEndian.Uint16(value[:2])
	// value[2:4] is reserved and ignored.
	l.MTID = binary.BigEndian.Uint16(value[4:6])
	l.Algorithm = value[6]
	// value[7] is reserved and ignored.
	l.Weight = binary.BigEndian.Uint32(value[8:12])

	l.SubTLVs, err = lsWalkSubTLVs(value[lsSrSegmentListFixedLen:], lsSrSegmentListSubTLVAlloc)
	return err
}

func (l *LsTLVSrSegmentList) Serialize() ([]byte, error) {
	buf := make([]byte, lsSrSegmentListFixedLen)
	binary.BigEndian.PutUint16(buf[:2], l.Flags)
	binary.BigEndian.PutUint16(buf[4:6], l.MTID)
	buf[6] = l.Algorithm
	binary.BigEndian.PutUint32(buf[8:12], l.Weight)

	sub, err := lsSerializeSubTLVs(l.SubTLVs)
	if err != nil {
		return nil, err
	}
	buf = append(buf, sub...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrSegmentList) String() string {
	subs := make([]string, 0, len(l.SubTLVs))
	for _, sub := range l.SubTLVs {
		subs = append(subs, sub.String())
	}
	return fmt.Sprintf("{SR Segment List: Weight:%d MTID:%d Algo:%d Flags:%s %s}",
		l.Weight, l.MTID, l.Algorithm, lsFlagLetters(l.Flags, "DECVRFATM"), strings.Join(subs, " "))
}

func (l *LsTLVSrSegmentList) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrSegmentList
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrSegmentList) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Candidate Path Constraints TLV (1204), RFC 9857 Section 5.6

const (
	lsSrCPConstraintsFlagSRv6            uint16 = 1 << 15 // D-Flag
	lsSrCPConstraintsFlagProtectedOnly   uint16 = 1 << 14 // P-Flag
	lsSrCPConstraintsFlagUnprotectedOnly uint16 = 1 << 13 // U-Flag
	lsSrCPConstraintsFlagAlgorithmOnly   uint16 = 1 << 12 // A-Flag
	lsSrCPConstraintsFlagTopologyOnly    uint16 = 1 << 11 // T-Flag
	lsSrCPConstraintsFlagStrict          uint16 = 1 << 10 // S-Flag
	lsSrCPConstraintsFlagFixed           uint16 = 1 << 9  // F-Flag
	lsSrCPConstraintsFlagHopByHop        uint16 = 1 << 8  // H-Flag
)

type LsSrCandidatePathConstraintsFlags struct {
	SRv6            bool `json:"srv6"`
	ProtectedOnly   bool `json:"protected_only"`
	UnprotectedOnly bool `json:"unprotected_only"`
	AlgorithmOnly   bool `json:"algorithm_only"`
	TopologyOnly    bool `json:"topology_only"`
	Strict          bool `json:"strict"`
	Fixed           bool `json:"fixed"`
	HopByHop        bool `json:"hop_by_hop"`
}

// LsSrCandidatePathConstraints is the native model of the SR Candidate Path
// Constraints TLV. The single-instance sub-TLVs are pointers or slices that
// are empty when absent; the Metric Constraint sub-TLV may appear once per
// metric type.
type LsSrCandidatePathConstraints struct {
	Flags              LsSrCandidatePathConstraintsFlags `json:"flags"`
	MTID               uint16                            `json:"mtid"`
	Algorithm          uint8                             `json:"algorithm"`
	Affinity           *LsSrAffinityConstraint           `json:"affinity,omitempty"`
	SRLGs              []uint32                          `json:"srlgs,omitempty"`
	Bandwidth          *float32                          `json:"bandwidth,omitempty"`
	DisjointGroup      *LsSrDisjointGroupConstraint      `json:"disjoint_group,omitempty"`
	BidirectionalGroup *LsSrBidirectionalGroupConstraint `json:"bidirectional_group,omitempty"`
	Metrics            []LsSrMetricConstraint            `json:"metrics,omitempty"`
}

type LsTLVSrCandidatePathConstraints struct {
	LsTLV
	Flags     uint16
	MTID      uint16
	Algorithm uint8
	SubTLVs   []LsTLVInterface
}

const lsSrCPConstraintsFixedLen = 8

func NewLsTLVSrCandidatePathConstraints(c *LsSrCandidatePathConstraints) *LsTLVSrCandidatePathConstraints {
	var flags uint16
	set := func(on bool, bit uint16) {
		if on {
			flags |= bit
		}
	}
	set(c.Flags.SRv6, lsSrCPConstraintsFlagSRv6)
	set(c.Flags.ProtectedOnly, lsSrCPConstraintsFlagProtectedOnly)
	set(c.Flags.UnprotectedOnly, lsSrCPConstraintsFlagUnprotectedOnly)
	set(c.Flags.AlgorithmOnly, lsSrCPConstraintsFlagAlgorithmOnly)
	set(c.Flags.TopologyOnly, lsSrCPConstraintsFlagTopologyOnly)
	set(c.Flags.Strict, lsSrCPConstraintsFlagStrict)
	set(c.Flags.Fixed, lsSrCPConstraintsFlagFixed)
	set(c.Flags.HopByHop, lsSrCPConstraintsFlagHopByHop)

	subTLVs := []LsTLVInterface{}
	if c.Affinity != nil {
		subTLVs = append(subTLVs, NewLsTLVSrAffinityConstraint(c.Affinity))
	}
	if len(c.SRLGs) > 0 {
		subTLVs = append(subTLVs, NewLsTLVSrSRLGConstraint(c.SRLGs))
	}
	if c.Bandwidth != nil {
		subTLVs = append(subTLVs, NewLsTLVSrBandwidthConstraint(c.Bandwidth))
	}
	if c.DisjointGroup != nil {
		subTLVs = append(subTLVs, NewLsTLVSrDisjointGroupConstraint(c.DisjointGroup))
	}
	if c.BidirectionalGroup != nil {
		subTLVs = append(subTLVs, NewLsTLVSrBidirectionalGroupConstraint(c.BidirectionalGroup))
	}
	for i := range c.Metrics {
		subTLVs = append(subTLVs, NewLsTLVSrMetricConstraint(&c.Metrics[i]))
	}

	return &LsTLVSrCandidatePathConstraints{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_CP_CONSTRAINTS,
			Length: uint16(lsSrCPConstraintsFixedLen + lsSubTLVsLen(subTLVs)),
		},
		Flags:     flags,
		MTID:      c.MTID,
		Algorithm: c.Algorithm,
		SubTLVs:   subTLVs,
	}
}

// Extract returns the native model. Single-instance sub-TLVs use the first
// instance; the rest are ignored as RFC 9857 requires.
func (l *LsTLVSrCandidatePathConstraints) Extract() *LsSrCandidatePathConstraints {
	c := &LsSrCandidatePathConstraints{
		Flags: LsSrCandidatePathConstraintsFlags{
			SRv6:            l.Flags&lsSrCPConstraintsFlagSRv6 != 0,
			ProtectedOnly:   l.Flags&lsSrCPConstraintsFlagProtectedOnly != 0,
			UnprotectedOnly: l.Flags&lsSrCPConstraintsFlagUnprotectedOnly != 0,
			AlgorithmOnly:   l.Flags&lsSrCPConstraintsFlagAlgorithmOnly != 0,
			TopologyOnly:    l.Flags&lsSrCPConstraintsFlagTopologyOnly != 0,
			Strict:          l.Flags&lsSrCPConstraintsFlagStrict != 0,
			Fixed:           l.Flags&lsSrCPConstraintsFlagFixed != 0,
			HopByHop:        l.Flags&lsSrCPConstraintsFlagHopByHop != 0,
		},
		MTID:      l.MTID,
		Algorithm: l.Algorithm,
	}

	for _, sub := range l.SubTLVs {
		switch v := sub.(type) {
		case *LsTLVSrAffinityConstraint:
			if c.Affinity == nil {
				c.Affinity = v.Extract()
			}
		case *LsTLVSrSRLGConstraint:
			if c.SRLGs == nil {
				c.SRLGs = append([]uint32(nil), v.SRLGs...)
			}
		case *LsTLVSrBandwidthConstraint:
			if c.Bandwidth == nil && lsValidBandwidth(v.Bandwidth) {
				bw := v.Bandwidth
				c.Bandwidth = &bw
			}
		case *LsTLVSrDisjointGroupConstraint:
			if c.DisjointGroup == nil {
				c.DisjointGroup = v.Extract()
			}
		case *LsTLVSrBidirectionalGroupConstraint:
			if c.BidirectionalGroup == nil {
				c.BidirectionalGroup = v.Extract()
			}
		case *LsTLVSrMetricConstraint:
			c.Metrics = append(c.Metrics, *v.Extract())
		}
	}

	return c
}

func lsSrCPConstraintsSubTLVAlloc(t LsTLVType) LsTLVInterface {
	switch t {
	case LS_TLV_SR_AFFINITY_CONSTRAINT:
		return &LsTLVSrAffinityConstraint{}
	case LS_TLV_SR_SRLG_CONSTRAINT:
		return &LsTLVSrSRLGConstraint{}
	case LS_TLV_SR_BANDWIDTH_CONSTRAINT:
		return &LsTLVSrBandwidthConstraint{}
	case LS_TLV_SR_DISJOINT_GROUP_CONSTRAINT:
		return &LsTLVSrDisjointGroupConstraint{}
	case LS_TLV_SR_BIDIR_GROUP_CONSTRAINT:
		return &LsTLVSrBidirectionalGroupConstraint{}
	case LS_TLV_SR_METRIC_CONSTRAINT:
		return &LsTLVSrMetricConstraint{}
	}
	return nil
}

func (l *LsTLVSrCandidatePathConstraints) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_CP_CONSTRAINTS {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < lsSrCPConstraintsFixedLen {
		return malformedAttrListErr("Incorrect SR Candidate Path Constraints length")
	}

	l.Flags = binary.BigEndian.Uint16(value[:2])
	// value[2:4] is reserved and ignored.
	l.MTID = binary.BigEndian.Uint16(value[4:6])
	l.Algorithm = value[6]
	// value[7] is reserved and ignored.

	l.SubTLVs, err = lsWalkSubTLVs(value[lsSrCPConstraintsFixedLen:], lsSrCPConstraintsSubTLVAlloc)
	return err
}

func (l *LsTLVSrCandidatePathConstraints) Serialize() ([]byte, error) {
	buf := make([]byte, lsSrCPConstraintsFixedLen)
	binary.BigEndian.PutUint16(buf[:2], l.Flags)
	binary.BigEndian.PutUint16(buf[4:6], l.MTID)
	buf[6] = l.Algorithm

	sub, err := lsSerializeSubTLVs(l.SubTLVs)
	if err != nil {
		return nil, err
	}
	buf = append(buf, sub...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrCandidatePathConstraints) String() string {
	subs := make([]string, 0, len(l.SubTLVs))
	for _, sub := range l.SubTLVs {
		subs = append(subs, sub.String())
	}
	s := fmt.Sprintf("{SR CP Constraints: MTID:%d Algo:%d Flags:%s", l.MTID, l.Algorithm, lsFlagLetters(l.Flags, "DPUATSFH"))
	if len(subs) > 0 {
		s += " " + strings.Join(subs, " ")
	}
	return s + "}"
}

func (l *LsTLVSrCandidatePathConstraints) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrCandidatePathConstraints
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrCandidatePathConstraints) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Affinity Constraint sub-TLV (1208), RFC 9857 Section 5.6.1

// LsSrAffinityConstraint carries the Extended Administrative Group (RFC 7308)
// bit masks of the candidate path. Each mask is a sequence of 32-bit words,
// the first word holding bits 0 to 31.
type LsSrAffinityConstraint struct {
	ExcludeAny []uint32 `json:"exclude_any,omitempty"`
	IncludeAny []uint32 `json:"include_any,omitempty"`
	IncludeAll []uint32 `json:"include_all,omitempty"`
}

type LsTLVSrAffinityConstraint struct {
	LsTLV
	ExcludeAny []uint32
	IncludeAny []uint32
	IncludeAll []uint32
}

// lsSrEAGMaxWords is the largest bit mask a 1-octet size field can describe.
const lsSrEAGMaxWords = 0xff

func NewLsTLVSrAffinityConstraint(a *LsSrAffinityConstraint) *LsTLVSrAffinityConstraint {
	return &LsTLVSrAffinityConstraint{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_AFFINITY_CONSTRAINT,
			Length: uint16(4 + 4*(len(a.ExcludeAny)+len(a.IncludeAny)+len(a.IncludeAll))),
		},
		ExcludeAny: append([]uint32(nil), a.ExcludeAny...),
		IncludeAny: append([]uint32(nil), a.IncludeAny...),
		IncludeAll: append([]uint32(nil), a.IncludeAll...),
	}
}

func (l *LsTLVSrAffinityConstraint) Extract() *LsSrAffinityConstraint {
	return &LsSrAffinityConstraint{
		ExcludeAny: append([]uint32(nil), l.ExcludeAny...),
		IncludeAny: append([]uint32(nil), l.IncludeAny...),
		IncludeAll: append([]uint32(nil), l.IncludeAll...),
	}
}

func lsSrEAGWords(b []byte) []uint32 {
	if len(b) == 0 {
		return nil
	}
	words := make([]uint32, 0, len(b)/4)
	for i := 0; i+4 <= len(b); i += 4 {
		words = append(words, binary.BigEndian.Uint32(b[i:i+4]))
	}
	return words
}

func lsSrEAGBytes(words []uint32) []byte {
	b := make([]byte, 0, 4*len(words))
	for _, w := range words {
		b = binary.BigEndian.AppendUint32(b, w)
	}
	return b
}

func lsSrEAGString(words []uint32) string {
	if len(words) == 0 {
		return "-"
	}
	s := make([]string, 0, len(words))
	for _, w := range words {
		s = append(s, fmt.Sprintf("0x%08x", w))
	}
	return strings.Join(s, ",")
}

func (l *LsTLVSrAffinityConstraint) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_AFFINITY_CONSTRAINT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 4 {
		return malformedAttrListErr("Incorrect SR Affinity Constraint length")
	}

	exclAny, inclAny, inclAll := int(value[0]), int(value[1]), int(value[2])
	// value[3] is reserved and ignored.
	if len(value) != 4+4*(exclAny+inclAny+inclAll) {
		return malformedAttrListErr("SR Affinity Constraint length does not match the EAG sizes")
	}

	rest := value[4:]
	l.ExcludeAny = lsSrEAGWords(rest[:4*exclAny])
	rest = rest[4*exclAny:]
	l.IncludeAny = lsSrEAGWords(rest[:4*inclAny])
	rest = rest[4*inclAny:]
	l.IncludeAll = lsSrEAGWords(rest[:4*inclAll])

	return nil
}

func (l *LsTLVSrAffinityConstraint) Serialize() ([]byte, error) {
	if len(l.ExcludeAny) > lsSrEAGMaxWords || len(l.IncludeAny) > lsSrEAGMaxWords || len(l.IncludeAll) > lsSrEAGMaxWords {
		return nil, errors.New("SR Affinity Constraint EAG exceeds 255 words")
	}

	buf := []byte{byte(len(l.ExcludeAny)), byte(len(l.IncludeAny)), byte(len(l.IncludeAll)), 0}
	buf = append(buf, lsSrEAGBytes(l.ExcludeAny)...)
	buf = append(buf, lsSrEAGBytes(l.IncludeAny)...)
	buf = append(buf, lsSrEAGBytes(l.IncludeAll)...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrAffinityConstraint) String() string {
	return fmt.Sprintf("{Affinity: ExclAny:%s InclAny:%s InclAll:%s}",
		lsSrEAGString(l.ExcludeAny), lsSrEAGString(l.IncludeAny), lsSrEAGString(l.IncludeAll))
}

func (l *LsTLVSrAffinityConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrAffinityConstraint
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrAffinityConstraint) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR SRLG Constraint sub-TLV (1209), RFC 9857 Section 5.6.2

type LsTLVSrSRLGConstraint struct {
	LsTLV
	SRLGs []uint32
}

func NewLsTLVSrSRLGConstraint(srlgs []uint32) *LsTLVSrSRLGConstraint {
	return &LsTLVSrSRLGConstraint{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_SRLG_CONSTRAINT,
			Length: uint16(4 * len(srlgs)),
		},
		SRLGs: append([]uint32(nil), srlgs...),
	}
}

func (l *LsTLVSrSRLGConstraint) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_SRLG_CONSTRAINT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) == 0 || len(value)%4 != 0 {
		return malformedAttrListErr("Incorrect SR SRLG Constraint length")
	}

	l.SRLGs = lsSrEAGWords(value)

	return nil
}

func (l *LsTLVSrSRLGConstraint) Serialize() ([]byte, error) {
	if len(l.SRLGs) == 0 {
		return nil, errors.New("SR SRLG Constraint requires at least one SRLG")
	}
	return l.LsTLV.Serialize(lsSrEAGBytes(l.SRLGs))
}

func (l *LsTLVSrSRLGConstraint) String() string {
	return fmt.Sprintf("{SRLG: %v}", l.SRLGs)
}

func (l *LsTLVSrSRLGConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		SRLGs []uint32  `json:"srlgs"`
	}{
		l.Type,
		l.SRLGs,
	})
}

func (l *LsTLVSrSRLGConstraint) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Bandwidth Constraint sub-TLV (1210), RFC 9857 Section 5.6.3

type LsTLVSrBandwidthConstraint struct {
	LsTLV
	Bandwidth float32
}

func NewLsTLVSrBandwidthConstraint(bw *float32) *LsTLVSrBandwidthConstraint {
	return &LsTLVSrBandwidthConstraint{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_BANDWIDTH_CONSTRAINT,
			Length: 4,
		},
		Bandwidth: *bw,
	}
}

func (l *LsTLVSrBandwidthConstraint) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_BANDWIDTH_CONSTRAINT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) != 4 {
		return malformedAttrListErr("Incorrect SR Bandwidth Constraint length")
	}

	// The value is not checked: RFC 9552 section 8.2.2 forbids treating
	// the attribute as malformed based on TLV contents. lsValidBandwidth
	// keeps a nonsensical value out of the model instead.
	l.Bandwidth = math.Float32frombits(binary.BigEndian.Uint32(value))

	return nil
}

func (l *LsTLVSrBandwidthConstraint) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, math.Float32bits(l.Bandwidth))

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrBandwidthConstraint) String() string {
	return fmt.Sprintf("{Bandwidth: %v}", l.Bandwidth)
}

func (l *LsTLVSrBandwidthConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsTLVType `json:"type"`
		Bandwidth float32   `json:"bandwidth"`
	}{
		l.Type,
		l.Bandwidth,
	})
}

func (l *LsTLVSrBandwidthConstraint) GetLsTLV() LsTLV {
	return l.LsTLV
}

// Group identifiers shared by the Disjoint Group and Bidirectional Group
// Constraint sub-TLVs. The identifier is a 4-octet group ID, or the whole
// PCEP ASSOCIATION Object when the producer cannot map it to 4 octets.

func lsSrGroupIdentifier(groupID uint32, association []byte) []byte {
	if len(association) > 0 {
		return append([]byte(nil), association...)
	}
	return binary.BigEndian.AppendUint32(nil, groupID)
}

func lsSrGroupIdentifierSplit(id []byte) (uint32, []byte) {
	if len(id) == 4 {
		return binary.BigEndian.Uint32(id), nil
	}
	return 0, append([]byte(nil), id...)
}

func lsSrGroupIdentifierString(id []byte) string {
	if len(id) == 4 {
		return strconv.FormatUint(uint64(binary.BigEndian.Uint32(id)), 10)
	}
	return fmt.Sprintf("%x", id)
}

// SR Disjoint Group Constraint sub-TLV (1211), RFC 9857 Section 5.6.4

const (
	lsSrDisjointGroupFlagSRLG             uint8 = 1 << 7 // S-Flag
	lsSrDisjointGroupFlagNode             uint8 = 1 << 6 // N-Flag
	lsSrDisjointGroupFlagLink             uint8 = 1 << 5 // L-Flag
	lsSrDisjointGroupFlagFallback         uint8 = 1 << 4 // F-Flag
	lsSrDisjointGroupFlagBestPathFallback uint8 = 1 << 3 // I-Flag
	lsSrDisjointGroupFlagInvalidated      uint8 = 1 << 2 // X-Flag, status only
)

type LsSrDisjointGroupRequestFlags struct {
	SRLG             bool `json:"srlg"`
	Node             bool `json:"node"`
	Link             bool `json:"link"`
	Fallback         bool `json:"fallback"`
	BestPathFallback bool `json:"best_path_fallback"`
}

type LsSrDisjointGroupStatusFlags struct {
	SRLG             bool `json:"srlg"`
	Node             bool `json:"node"`
	Link             bool `json:"link"`
	Fallback         bool `json:"fallback"`
	BestPathFallback bool `json:"best_path_fallback"`
	Invalidated      bool `json:"invalidated"`
}

type LsSrDisjointGroupConstraint struct {
	RequestFlags    LsSrDisjointGroupRequestFlags `json:"request_flags"`
	StatusFlags     LsSrDisjointGroupStatusFlags  `json:"status_flags"`
	GroupID         uint32                        `json:"group_id"`
	PcepAssociation []byte                        `json:"pcep_association,omitempty"`
}

type LsTLVSrDisjointGroupConstraint struct {
	LsTLV
	RequestFlags uint8
	StatusFlags  uint8
	Identifier   []byte
}

func NewLsTLVSrDisjointGroupConstraint(d *LsSrDisjointGroupConstraint) *LsTLVSrDisjointGroupConstraint {
	var request, status uint8
	set := func(flags *uint8, on bool, bit uint8) {
		if on {
			*flags |= bit
		}
	}
	set(&request, d.RequestFlags.SRLG, lsSrDisjointGroupFlagSRLG)
	set(&request, d.RequestFlags.Node, lsSrDisjointGroupFlagNode)
	set(&request, d.RequestFlags.Link, lsSrDisjointGroupFlagLink)
	set(&request, d.RequestFlags.Fallback, lsSrDisjointGroupFlagFallback)
	set(&request, d.RequestFlags.BestPathFallback, lsSrDisjointGroupFlagBestPathFallback)
	set(&status, d.StatusFlags.SRLG, lsSrDisjointGroupFlagSRLG)
	set(&status, d.StatusFlags.Node, lsSrDisjointGroupFlagNode)
	set(&status, d.StatusFlags.Link, lsSrDisjointGroupFlagLink)
	set(&status, d.StatusFlags.Fallback, lsSrDisjointGroupFlagFallback)
	set(&status, d.StatusFlags.BestPathFallback, lsSrDisjointGroupFlagBestPathFallback)
	set(&status, d.StatusFlags.Invalidated, lsSrDisjointGroupFlagInvalidated)

	id := lsSrGroupIdentifier(d.GroupID, d.PcepAssociation)
	return &LsTLVSrDisjointGroupConstraint{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_DISJOINT_GROUP_CONSTRAINT,
			Length: uint16(4 + len(id)),
		},
		RequestFlags: request,
		StatusFlags:  status,
		Identifier:   id,
	}
}

func (l *LsTLVSrDisjointGroupConstraint) Extract() *LsSrDisjointGroupConstraint {
	groupID, association := lsSrGroupIdentifierSplit(l.Identifier)
	return &LsSrDisjointGroupConstraint{
		RequestFlags: LsSrDisjointGroupRequestFlags{
			SRLG:             l.RequestFlags&lsSrDisjointGroupFlagSRLG != 0,
			Node:             l.RequestFlags&lsSrDisjointGroupFlagNode != 0,
			Link:             l.RequestFlags&lsSrDisjointGroupFlagLink != 0,
			Fallback:         l.RequestFlags&lsSrDisjointGroupFlagFallback != 0,
			BestPathFallback: l.RequestFlags&lsSrDisjointGroupFlagBestPathFallback != 0,
		},
		StatusFlags: LsSrDisjointGroupStatusFlags{
			SRLG:             l.StatusFlags&lsSrDisjointGroupFlagSRLG != 0,
			Node:             l.StatusFlags&lsSrDisjointGroupFlagNode != 0,
			Link:             l.StatusFlags&lsSrDisjointGroupFlagLink != 0,
			Fallback:         l.StatusFlags&lsSrDisjointGroupFlagFallback != 0,
			BestPathFallback: l.StatusFlags&lsSrDisjointGroupFlagBestPathFallback != 0,
			Invalidated:      l.StatusFlags&lsSrDisjointGroupFlagInvalidated != 0,
		},
		GroupID:         groupID,
		PcepAssociation: association,
	}
}

func (l *LsTLVSrDisjointGroupConstraint) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_DISJOINT_GROUP_CONSTRAINT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 8 {
		return malformedAttrListErr("Incorrect SR Disjoint Group Constraint length")
	}

	l.RequestFlags = value[0]
	l.StatusFlags = value[1]
	// value[2:4] is reserved and ignored.
	l.Identifier = append([]byte(nil), value[4:]...)

	return nil
}

func (l *LsTLVSrDisjointGroupConstraint) Serialize() ([]byte, error) {
	if len(l.Identifier) < 4 {
		return nil, errors.New("SR Disjoint Group Constraint requires a group identifier")
	}
	buf := []byte{l.RequestFlags, l.StatusFlags, 0, 0}
	buf = append(buf, l.Identifier...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrDisjointGroupConstraint) String() string {
	return fmt.Sprintf("{Disjoint Group: ID:%s Request:%s Status:%s}",
		lsSrGroupIdentifierString(l.Identifier),
		lsFlagLetters(uint16(l.RequestFlags)<<8, "SNLFI"),
		lsFlagLetters(uint16(l.StatusFlags)<<8, "SNLFIX"))
}

func (l *LsTLVSrDisjointGroupConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrDisjointGroupConstraint
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrDisjointGroupConstraint) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Bidirectional Group Constraint sub-TLV (1214), RFC 9857 Section 5.6.5

const (
	lsSrBidirectionalGroupFlagReverse  uint16 = 1 << 15 // R-Flag
	lsSrBidirectionalGroupFlagCoRouted uint16 = 1 << 14 // C-Flag
)

type LsSrBidirectionalGroupFlags struct {
	Reverse  bool `json:"reverse"`
	CoRouted bool `json:"co_routed"`
}

type LsSrBidirectionalGroupConstraint struct {
	Flags           LsSrBidirectionalGroupFlags `json:"flags"`
	GroupID         uint32                      `json:"group_id"`
	PcepAssociation []byte                      `json:"pcep_association,omitempty"`
}

type LsTLVSrBidirectionalGroupConstraint struct {
	LsTLV
	Flags      uint16
	Identifier []byte
}

func NewLsTLVSrBidirectionalGroupConstraint(b *LsSrBidirectionalGroupConstraint) *LsTLVSrBidirectionalGroupConstraint {
	var flags uint16
	if b.Flags.Reverse {
		flags |= lsSrBidirectionalGroupFlagReverse
	}
	if b.Flags.CoRouted {
		flags |= lsSrBidirectionalGroupFlagCoRouted
	}

	id := lsSrGroupIdentifier(b.GroupID, b.PcepAssociation)
	return &LsTLVSrBidirectionalGroupConstraint{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_BIDIR_GROUP_CONSTRAINT,
			Length: uint16(4 + len(id)),
		},
		Flags:      flags,
		Identifier: id,
	}
}

func (l *LsTLVSrBidirectionalGroupConstraint) Extract() *LsSrBidirectionalGroupConstraint {
	groupID, association := lsSrGroupIdentifierSplit(l.Identifier)
	return &LsSrBidirectionalGroupConstraint{
		Flags: LsSrBidirectionalGroupFlags{
			Reverse:  l.Flags&lsSrBidirectionalGroupFlagReverse != 0,
			CoRouted: l.Flags&lsSrBidirectionalGroupFlagCoRouted != 0,
		},
		GroupID:         groupID,
		PcepAssociation: association,
	}
}

func (l *LsTLVSrBidirectionalGroupConstraint) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_BIDIR_GROUP_CONSTRAINT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 8 {
		return malformedAttrListErr("Incorrect SR Bidirectional Group Constraint length")
	}

	l.Flags = binary.BigEndian.Uint16(value[:2])
	// value[2:4] is reserved and ignored.
	l.Identifier = append([]byte(nil), value[4:]...)

	return nil
}

func (l *LsTLVSrBidirectionalGroupConstraint) Serialize() ([]byte, error) {
	if len(l.Identifier) < 4 {
		return nil, errors.New("SR Bidirectional Group Constraint requires a group identifier")
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[:2], l.Flags)
	buf = append(buf, l.Identifier...)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrBidirectionalGroupConstraint) String() string {
	return fmt.Sprintf("{Bidirectional Group: ID:%s Flags:%s}",
		lsSrGroupIdentifierString(l.Identifier), lsFlagLetters(l.Flags, "RC"))
}

func (l *LsTLVSrBidirectionalGroupConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrBidirectionalGroupConstraint
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrBidirectionalGroupConstraint) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Metric Constraint sub-TLV (1215), RFC 9857 Section 5.6.6

const (
	lsSrMetricConstraintFlagOptimization uint8 = 1 << 7 // O-Flag
	lsSrMetricConstraintFlagMargin       uint8 = 1 << 6 // M-Flag
	lsSrMetricConstraintFlagAbsolute     uint8 = 1 << 5 // A-Flag
	lsSrMetricConstraintFlagBound        uint8 = 1 << 4 // B-Flag
)

type LsSrMetricConstraintFlags struct {
	Optimization bool `json:"optimization"`
	Margin       bool `json:"margin"`
	Absolute     bool `json:"absolute"`
	Bound        bool `json:"bound"`
}

type LsSrMetricConstraint struct {
	MetricType uint8                     `json:"metric_type"`
	Flags      LsSrMetricConstraintFlags `json:"flags"`
	Margin     uint32                    `json:"margin"`
	Bound      uint32                    `json:"bound"`
}

type LsTLVSrMetricConstraint struct {
	LsTLV
	MetricType uint8
	Flags      uint8
	Margin     uint32
	Bound      uint32
}

func NewLsTLVSrMetricConstraint(m *LsSrMetricConstraint) *LsTLVSrMetricConstraint {
	var flags uint8
	if m.Flags.Optimization {
		flags |= lsSrMetricConstraintFlagOptimization
	}
	if m.Flags.Margin {
		flags |= lsSrMetricConstraintFlagMargin
	}
	if m.Flags.Absolute {
		flags |= lsSrMetricConstraintFlagAbsolute
	}
	if m.Flags.Bound {
		flags |= lsSrMetricConstraintFlagBound
	}

	return &LsTLVSrMetricConstraint{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_METRIC_CONSTRAINT,
			Length: 12,
		},
		MetricType: m.MetricType,
		Flags:      flags,
		Margin:     m.Margin,
		Bound:      m.Bound,
	}
}

func (l *LsTLVSrMetricConstraint) Extract() *LsSrMetricConstraint {
	return &LsSrMetricConstraint{
		MetricType: l.MetricType,
		Flags: LsSrMetricConstraintFlags{
			Optimization: l.Flags&lsSrMetricConstraintFlagOptimization != 0,
			Margin:       l.Flags&lsSrMetricConstraintFlagMargin != 0,
			Absolute:     l.Flags&lsSrMetricConstraintFlagAbsolute != 0,
			Bound:        l.Flags&lsSrMetricConstraintFlagBound != 0,
		},
		Margin: l.Margin,
		Bound:  l.Bound,
	}
}

func (l *LsTLVSrMetricConstraint) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_METRIC_CONSTRAINT {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) != 12 {
		return malformedAttrListErr("Incorrect SR Metric Constraint length")
	}

	l.MetricType = value[0]
	l.Flags = value[1]
	// value[2:4] is reserved and ignored.
	l.Margin = binary.BigEndian.Uint32(value[4:8])
	l.Bound = binary.BigEndian.Uint32(value[8:12])

	return nil
}

func (l *LsTLVSrMetricConstraint) Serialize() ([]byte, error) {
	buf := make([]byte, 12)
	buf[0] = l.MetricType
	buf[1] = l.Flags
	binary.BigEndian.PutUint32(buf[4:8], l.Margin)
	binary.BigEndian.PutUint32(buf[8:12], l.Bound)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrMetricConstraint) String() string {
	return fmt.Sprintf("{Metric Constraint: Type:%d Margin:%d Bound:%d Flags:%s}",
		l.MetricType, l.Margin, l.Bound, lsFlagLetters(uint16(l.Flags)<<8, "OMAB"))
}

func (l *LsTLVSrMetricConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrMetricConstraint
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrMetricConstraint) GetLsTLV() LsTLV {
	return l.LsTLV
}

// LsAttribute helpers

// NewLsAttributeSrPolicyTLVs builds the RFC 9857 attribute TLVs for an SR
// Policy candidate path, in a fixed order: SR Binding SID, SRv6 Binding SID,
// Candidate Path State, Candidate Path Name, Policy Name, Candidate Path
// Constraints and then one SR Segment List TLV per segment list.
func NewLsAttributeSrPolicyTLVs(sp *LsAttributeSrPolicy) []LsTLVInterface {
	tlvs := []LsTLVInterface{}

	if sp.BindingSID != nil {
		tlvs = append(tlvs, NewLsTLVSrBindingSID(sp.BindingSID))
	}
	for i := range sp.Srv6BindingSIDs {
		tlvs = append(tlvs, NewLsTLVSrv6BindingSID(&sp.Srv6BindingSIDs[i]))
	}
	if sp.State != nil {
		tlvs = append(tlvs, NewLsTLVSrCandidatePathState(sp.State))
	}
	if sp.CandidatePathName != nil {
		tlvs = append(tlvs, NewLsTLVSrCandidatePathName(sp.CandidatePathName))
	}
	if sp.PolicyName != nil {
		tlvs = append(tlvs, NewLsTLVSrPolicyName(sp.PolicyName))
	}
	if sp.Constraints != nil {
		tlvs = append(tlvs, NewLsTLVSrCandidatePathConstraints(sp.Constraints))
	}
	for i := range sp.SegmentLists {
		tlvs = append(tlvs, NewLsTLVSrSegmentList(&sp.SegmentLists[i]))
	}

	return tlvs
}
