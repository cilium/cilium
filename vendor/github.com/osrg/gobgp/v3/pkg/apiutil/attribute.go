// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"google.golang.org/protobuf/proto"
	apb "google.golang.org/protobuf/types/known/anypb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func UnmarshalAttribute(an *apb.Any) (bgp.PathAttributeInterface, error) {
	value, err := an.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal route distinguisher: %s", err)
	}
	switch a := value.(type) {
	case *api.OriginAttribute:
		return bgp.NewPathAttributeOrigin(uint8(a.Origin)), nil
	case *api.AsPathAttribute:
		params := make([]bgp.AsPathParamInterface, 0, len(a.Segments))
		for _, segment := range a.Segments {
			params = append(params, bgp.NewAs4PathParam(uint8(segment.Type), segment.Numbers))
		}
		return bgp.NewPathAttributeAsPath(params), nil
	case *api.NextHopAttribute:
		nexthop := net.ParseIP(a.NextHop).To4()
		if nexthop == nil {
			if nexthop = net.ParseIP(a.NextHop).To16(); nexthop == nil {
				return nil, fmt.Errorf("invalid nexthop address: %s", a.NextHop)
			}
		}
		return bgp.NewPathAttributeNextHop(a.NextHop), nil
	case *api.MultiExitDiscAttribute:
		return bgp.NewPathAttributeMultiExitDisc(a.Med), nil
	case *api.LocalPrefAttribute:
		return bgp.NewPathAttributeLocalPref(a.LocalPref), nil
	case *api.AtomicAggregateAttribute:
		return bgp.NewPathAttributeAtomicAggregate(), nil
	case *api.AggregatorAttribute:
		if net.ParseIP(a.Address).To4() == nil {
			return nil, fmt.Errorf("invalid aggregator address: %s", a.Address)
		}
		return bgp.NewPathAttributeAggregator(a.Asn, a.Address), nil
	case *api.CommunitiesAttribute:
		return bgp.NewPathAttributeCommunities(a.Communities), nil
	case *api.OriginatorIdAttribute:
		if net.ParseIP(a.Id).To4() == nil {
			return nil, fmt.Errorf("invalid originator id: %s", a.Id)
		}
		return bgp.NewPathAttributeOriginatorId(a.Id), nil
	case *api.ClusterListAttribute:
		for _, id := range a.Ids {
			if net.ParseIP(id).To4() == nil {
				return nil, fmt.Errorf("invalid cluster list: %s", a.Ids)
			}
		}
		return bgp.NewPathAttributeClusterList(a.Ids), nil
	case *api.MpReachNLRIAttribute:
		if a.Family == nil {
			return nil, fmt.Errorf("empty family")
		}
		rf := ToRouteFamily(a.Family)
		nlris, err := UnmarshalNLRIs(rf, a.Nlris)
		if err != nil {
			return nil, err
		}
		afi, safi := bgp.RouteFamilyToAfiSafi(rf)
		nexthop := "0.0.0.0"
		var linkLocalNexthop net.IP
		if afi == bgp.AFI_IP6 {
			nexthop = "::"
			if len(a.NextHops) > 1 {
				linkLocalNexthop = net.ParseIP(a.NextHops[1]).To16()
				if linkLocalNexthop == nil {
					return nil, fmt.Errorf("invalid nexthop: %s", a.NextHops[1])
				}
			}
		}
		if safi == bgp.SAFI_FLOW_SPEC_UNICAST || safi == bgp.SAFI_FLOW_SPEC_VPN {
			nexthop = ""
		} else if len(a.NextHops) > 0 {
			nexthop = a.NextHops[0]
			if net.ParseIP(nexthop) == nil {
				return nil, fmt.Errorf("invalid nexthop: %s", nexthop)
			}
		}
		attr := bgp.NewPathAttributeMpReachNLRI(nexthop, nlris)
		attr.LinkLocalNexthop = linkLocalNexthop
		return attr, nil
	case *api.MpUnreachNLRIAttribute:
		rf := ToRouteFamily(a.Family)
		nlris, err := UnmarshalNLRIs(rf, a.Nlris)
		if err != nil {
			return nil, err
		}
		return bgp.NewPathAttributeMpUnreachNLRI(nlris), nil
	case *api.ExtendedCommunitiesAttribute:
		return unmarshalExComm(a)
	case *api.As4PathAttribute:
		params := make([]*bgp.As4PathParam, 0, len(a.Segments))
		for _, segment := range a.Segments {
			params = append(params, bgp.NewAs4PathParam(uint8(segment.Type), segment.Numbers))
		}
		return bgp.NewPathAttributeAs4Path(params), nil
	case *api.As4AggregatorAttribute:
		if net.ParseIP(a.Address).To4() == nil {
			return nil, fmt.Errorf("invalid as4 aggregator address: %s", a.Address)
		}
		return bgp.NewPathAttributeAs4Aggregator(a.Asn, a.Address), nil
	case *api.PmsiTunnelAttribute:
		typ := bgp.PmsiTunnelType(a.Type)
		var isLeafInfoRequired bool
		if a.Flags&0x01 > 0 {
			isLeafInfoRequired = true
		}
		var id bgp.PmsiTunnelIDInterface
		switch typ {
		case bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL:
			ip := net.IP(a.Id)
			if ip.To4() == nil && ip.To16() == nil {
				return nil, fmt.Errorf("invalid pmsi tunnel identifier: %s", a.Id)
			}
			id = bgp.NewIngressReplTunnelID(ip.String())
		default:
			id = bgp.NewDefaultPmsiTunnelID(a.Id)
		}
		return bgp.NewPathAttributePmsiTunnel(typ, isLeafInfoRequired, a.Label, id), nil
	case *api.TunnelEncapAttribute:
		tlvs := make([]*bgp.TunnelEncapTLV, 0, len(a.Tlvs))
		for _, tlv := range a.Tlvs {
			subTlvs := make([]bgp.TunnelEncapSubTLVInterface, 0, len(tlv.Tlvs))
			for _, an := range tlv.Tlvs {
				var subTlv bgp.TunnelEncapSubTLVInterface
				subValue, err := an.UnmarshalNew()
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal tunnel encapsulation attribute sub tlv: %s", err)
				}
				switch sv := subValue.(type) {
				case *api.TunnelEncapSubTLVEncapsulation:
					subTlv = bgp.NewTunnelEncapSubTLVEncapsulation(sv.Key, sv.Cookie)
				case *api.TunnelEncapSubTLVProtocol:
					subTlv = bgp.NewTunnelEncapSubTLVProtocol(uint16(sv.Protocol))
				case *api.TunnelEncapSubTLVColor:
					subTlv = bgp.NewTunnelEncapSubTLVColor(sv.Color)
				case *api.TunnelEncapSubTLVEgressEndpoint:
					subTlv = bgp.NewTunnelEncapSubTLVEgressEndpoint(sv.Address)
				case *api.TunnelEncapSubTLVUDPDestPort:
					subTlv = bgp.NewTunnelEncapSubTLVUDPDestPort(uint16(sv.Port))
				case *api.TunnelEncapSubTLVSRPreference:
					subTlv = bgp.NewTunnelEncapSubTLVSRPreference(sv.Flags, sv.Preference)
				case *api.TunnelEncapSubTLVSRPriority:
					subTlv = bgp.NewTunnelEncapSubTLVSRPriority(uint8(sv.Priority))
				case *api.TunnelEncapSubTLVSRCandidatePathName:
					subTlv = bgp.NewTunnelEncapSubTLVSRCandidatePathName(sv.CandidatePathName)
				case *api.TunnelEncapSubTLVSRENLP:
					subTlv = bgp.NewTunnelEncapSubTLVSRENLP(sv.Flags, bgp.SRENLPValue(sv.Enlp))
				case *api.TunnelEncapSubTLVSRBindingSID:
					var err error
					subTlv, err = UnmarshalSRBSID(sv.Bsid)
					if err != nil {
						return nil, fmt.Errorf("failed to unmarshal tunnel encapsulation attribute sub tlv: %s", err)
					}
				case *api.TunnelEncapSubTLVSRSegmentList:
					var err error
					weight := uint32(0)
					flags := uint8(0)
					if sv.Weight != nil {
						weight = sv.Weight.Weight
						flags = uint8(sv.Weight.Flags)
					}
					s := &bgp.TunnelEncapSubTLVSRSegmentList{
						TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
							Type:   bgp.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
							Length: uint16(6), // Weight (6 bytes) + length of segment (added later, after all segments are discovered)
						},
						Weight: &bgp.SegmentListWeight{
							TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
								Type:   bgp.SegmentListSubTLVWeight,
								Length: uint16(6),
							},
							Flags:  flags,
							Weight: weight,
						},
						Segments: make([]bgp.TunnelEncapSubTLVInterface, 0),
					}
					if len(sv.Segments) != 0 {
						s.Segments, err = UnmarshalSRSegments(sv.Segments)
						if err != nil {
							return nil, fmt.Errorf("failed to unmarshal tunnel encapsulation attribute sub tlv: %s", err)
						}
					}
					// Get total length of Segment List Sub TLV
					for _, seg := range s.Segments {
						s.TunnelEncapSubTLV.Length += uint16(seg.Len() + 2) // Adding 1 byte of type and 1 byte of length for each Segment object
					}
					subTlv = s
				case *api.TunnelEncapSubTLVUnknown:
					subTlv = bgp.NewTunnelEncapSubTLVUnknown(bgp.EncapSubTLVType(sv.Type), sv.Value)
				default:
					return nil, fmt.Errorf("invalid tunnel encapsulation attribute sub tlv: %v type: %T", subValue, sv)
				}
				subTlvs = append(subTlvs, subTlv)
			}
			tlvs = append(tlvs, bgp.NewTunnelEncapTLV(bgp.TunnelType(tlv.Type), subTlvs))
		}
		return bgp.NewPathAttributeTunnelEncap(tlvs), nil
	case *api.IP6ExtendedCommunitiesAttribute:
		communities := make([]bgp.ExtendedCommunityInterface, 0, len(a.Communities))
		for _, an := range a.Communities {
			var community bgp.ExtendedCommunityInterface
			value, err := an.UnmarshalNew()
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal ipv6 extended community: %s", err)
			}
			switch v := value.(type) {
			case *api.IPv6AddressSpecificExtended:
				community = bgp.NewIPv6AddressSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Address, uint16(v.LocalAdmin), v.IsTransitive)
			case *api.RedirectIPv6AddressSpecificExtended:
				community = bgp.NewRedirectIPv6AddressSpecificExtended(v.Address, uint16(v.LocalAdmin))
			}
			if community == nil {
				return nil, fmt.Errorf("invalid ipv6 extended community: %v", value)
			}
			communities = append(communities, community)
		}
		return bgp.NewPathAttributeIP6ExtendedCommunities(communities), nil

	case *api.AigpAttribute:
		tlvs := make([]bgp.AigpTLVInterface, 0, len(a.Tlvs))
		for _, an := range a.Tlvs {
			var tlv bgp.AigpTLVInterface
			value, err := an.UnmarshalNew()
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal aigp attribute tlv: %s", err)
			}
			switch v := value.(type) {
			case *api.AigpTLVIGPMetric:
				tlv = bgp.NewAigpTLVIgpMetric(v.Metric)
			case *api.AigpTLVUnknown:
				tlv = bgp.NewAigpTLVDefault(bgp.AigpTLVType(v.Type), v.Value)
			}
			if tlv == nil {
				return nil, fmt.Errorf("invalid aigp attribute tlv: %v", value)
			}
			tlvs = append(tlvs, tlv)
		}
		return bgp.NewPathAttributeAigp(tlvs), nil

	case *api.LargeCommunitiesAttribute:
		communities := make([]*bgp.LargeCommunity, 0, len(a.Communities))
		for _, c := range a.Communities {
			communities = append(communities, bgp.NewLargeCommunity(c.GlobalAdmin, c.LocalData1, c.LocalData2))
		}
		return bgp.NewPathAttributeLargeCommunities(communities), nil
	case *api.PrefixSID:
		return UnmarshalPrefixSID(a)
	case *api.UnknownAttribute:
		return bgp.NewPathAttributeUnknown(bgp.BGPAttrFlag(a.Flags), bgp.BGPAttrType(a.Type), a.Value), nil
	}
	return nil, errors.New("unknown path attribute")
}

func NewOriginAttributeFromNative(a *bgp.PathAttributeOrigin) (*api.OriginAttribute, error) {
	return &api.OriginAttribute{
		Origin: uint32(a.Value),
	}, nil
}

func NewAsPathAttributeFromNative(a *bgp.PathAttributeAsPath) (*api.AsPathAttribute, error) {
	segments := make([]*api.AsSegment, 0, len(a.Value))
	for _, param := range a.Value {
		segments = append(segments, &api.AsSegment{
			Type:    api.AsSegment_Type(param.GetType()),
			Numbers: param.GetAS(),
		})
	}
	return &api.AsPathAttribute{
		Segments: segments,
	}, nil
}

func NewNextHopAttributeFromNative(a *bgp.PathAttributeNextHop) (*api.NextHopAttribute, error) {
	return &api.NextHopAttribute{
		NextHop: a.Value.String(),
	}, nil
}

func NewMultiExitDiscAttributeFromNative(a *bgp.PathAttributeMultiExitDisc) (*api.MultiExitDiscAttribute, error) {
	return &api.MultiExitDiscAttribute{
		Med: a.Value,
	}, nil
}

func NewLocalPrefAttributeFromNative(a *bgp.PathAttributeLocalPref) (*api.LocalPrefAttribute, error) {
	return &api.LocalPrefAttribute{
		LocalPref: a.Value,
	}, nil
}

func NewAtomicAggregateAttributeFromNative(a *bgp.PathAttributeAtomicAggregate) (*api.AtomicAggregateAttribute, error) {
	return &api.AtomicAggregateAttribute{}, nil
}

func NewAggregatorAttributeFromNative(a *bgp.PathAttributeAggregator) (*api.AggregatorAttribute, error) {
	return &api.AggregatorAttribute{
		Asn:     a.Value.AS,
		Address: a.Value.Address.String(),
	}, nil
}

func NewCommunitiesAttributeFromNative(a *bgp.PathAttributeCommunities) (*api.CommunitiesAttribute, error) {
	return &api.CommunitiesAttribute{
		Communities: a.Value,
	}, nil
}

func NewOriginatorIdAttributeFromNative(a *bgp.PathAttributeOriginatorId) (*api.OriginatorIdAttribute, error) {
	return &api.OriginatorIdAttribute{
		Id: a.Value.String(),
	}, nil
}

func NewClusterListAttributeFromNative(a *bgp.PathAttributeClusterList) (*api.ClusterListAttribute, error) {
	ids := make([]string, 0, len(a.Value))
	for _, id := range a.Value {
		ids = append(ids, id.String())
	}
	return &api.ClusterListAttribute{
		Ids: ids,
	}, nil
}

func NewPrefixSIDAttributeFromNative(a *bgp.PathAttributePrefixSID) (*api.PrefixSID, error) {
	var err error
	psid := &api.PrefixSID{}
	psid.Tlvs, err = MarshalSRv6TLVs(a.TLVs)
	if err != nil {
		return nil, err
	}
	return psid, nil
}

func MarshalSRv6TLVs(tlvs []bgp.PrefixSIDTLVInterface) ([]*apb.Any, error) {
	var err error
	mtlvs := make([]*apb.Any, len(tlvs))
	for i, tlv := range tlvs {
		var r proto.Message
		switch t := tlv.(type) {
		case *bgp.SRv6L3ServiceAttribute:
			o := &api.SRv6L3ServiceTLV{}
			o.SubTlvs, err = MarshalSRv6SubTLVs(t.SubTLVs)
			if err != nil {
				return nil, err
			}
			r = o
		default:
			return nil, fmt.Errorf("invalid prefix sid tlv type to marshal %v", t)
		}
		a, _ := apb.New(r)
		mtlvs[i] = a
	}

	return mtlvs, nil
}

func MarshalSRv6SubTLVs(tlvs []bgp.PrefixSIDTLVInterface) (map[uint32]*api.SRv6TLV, error) {
	mtlvs := make(map[uint32]*api.SRv6TLV)
	var key uint32
	for _, tlv := range tlvs {
		var r proto.Message
		switch t := tlv.(type) {
		case *bgp.SRv6InformationSubTLV:
			o := &api.SRv6InformationSubTLV{
				EndpointBehavior: uint32(t.EndpointBehavior),
				// TODO Once flags are used in RFC, add processing.
				Flags: &api.SRv6SIDFlags{},
			}
			o.Sid = make([]byte, len(t.SID))
			copy(o.Sid, t.SID)
			var err error
			o.SubSubTlvs, err = MarshalSRv6SubSubTLVs(t.SubSubTLVs)
			if err != nil {
				return nil, err
			}
			// SRv6 Information Sub TLV is type 1 Sub TLV
			key = 1
			r = o
		default:
			return nil, fmt.Errorf("invalid prefix sid sub tlv type to marshal: %v", t)
		}
		a, _ := apb.New(r)
		tlvs, ok := mtlvs[key]
		if !ok {
			tlvs = &api.SRv6TLV{
				Tlv: make([]*apb.Any, 0),
			}
			mtlvs[key] = tlvs
		}
		tlvs.Tlv = append(tlvs.Tlv, a)
	}

	return mtlvs, nil
}

func MarshalSRv6SubSubTLVs(tlvs []bgp.PrefixSIDTLVInterface) (map[uint32]*api.SRv6TLV, error) {
	mtlvs := make(map[uint32]*api.SRv6TLV)
	var key uint32
	for _, tlv := range tlvs {
		var r proto.Message
		switch t := tlv.(type) {
		case *bgp.SRv6SIDStructureSubSubTLV:
			o := &api.SRv6StructureSubSubTLV{
				LocalBlockLength:    uint32(t.LocalBlockLength),
				LocalNodeLength:     uint32(t.LocatorNodeLength),
				FunctionLength:      uint32(t.FunctionLength),
				ArgumentLength:      uint32(t.ArgumentLength),
				TranspositionLength: uint32(t.TranspositionLength),
				TranspositionOffset: uint32(t.TranspositionOffset),
			}
			// SRv6 SID Structure Sub Sub TLV is type 1 Sub Sub TLV
			key = 1
			r = o
		default:
			return nil, fmt.Errorf("invalid prefix sid sub sub tlv type to marshal: %v", t)
		}
		a, _ := apb.New(r)
		tlvs, ok := mtlvs[key]
		if !ok {
			tlvs = &api.SRv6TLV{
				Tlv: make([]*apb.Any, 0),
			}
			mtlvs[key] = tlvs
		}
		tlvs.Tlv = append(tlvs.Tlv, a)
	}
	return mtlvs, nil
}

func MarshalRD(rd bgp.RouteDistinguisherInterface) (*apb.Any, error) {
	var r proto.Message
	switch v := rd.(type) {
	case *bgp.RouteDistinguisherTwoOctetAS:
		r = &api.RouteDistinguisherTwoOctetASN{
			Admin:    uint32(v.Admin),
			Assigned: v.Assigned,
		}
	case *bgp.RouteDistinguisherIPAddressAS:
		r = &api.RouteDistinguisherIPAddress{
			Admin:    v.Admin.String(),
			Assigned: uint32(v.Assigned),
		}
	case *bgp.RouteDistinguisherFourOctetAS:
		r = &api.RouteDistinguisherFourOctetASN{
			Admin:    v.Admin,
			Assigned: uint32(v.Assigned),
		}
	default:
		return nil, fmt.Errorf("invalid rd type to marshal: %v", rd)
	}
	a, _ := apb.New(r)
	return a, nil
}

func UnmarshalRD(a *apb.Any) (bgp.RouteDistinguisherInterface, error) {
	value, err := a.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal route distinguisher: %s", err)
	}
	switch v := value.(type) {
	case *api.RouteDistinguisherTwoOctetASN:
		return bgp.NewRouteDistinguisherTwoOctetAS(uint16(v.Admin), v.Assigned), nil
	case *api.RouteDistinguisherIPAddress:
		rd := bgp.NewRouteDistinguisherIPAddressAS(v.Admin, uint16(v.Assigned))
		if rd == nil {
			return nil, fmt.Errorf("invalid address for route distinguisher: %s", v.Admin)
		}
		return rd, nil
	case *api.RouteDistinguisherFourOctetASN:
		return bgp.NewRouteDistinguisherFourOctetAS(v.Admin, uint16(v.Assigned)), nil
	}
	return nil, fmt.Errorf("invalid route distinguisher type: %s", a.TypeUrl)
}

func NewEthernetSegmentIdentifierFromNative(a *bgp.EthernetSegmentIdentifier) (*api.EthernetSegmentIdentifier, error) {
	return &api.EthernetSegmentIdentifier{
		Type:  uint32(a.Type),
		Value: a.Value,
	}, nil
}

func unmarshalESI(a *api.EthernetSegmentIdentifier) (*bgp.EthernetSegmentIdentifier, error) {
	return &bgp.EthernetSegmentIdentifier{
		Type:  bgp.ESIType(a.Type),
		Value: a.Value,
	}, nil
}

func MarshalFlowSpecRules(values []bgp.FlowSpecComponentInterface) ([]*apb.Any, error) {
	rules := make([]*apb.Any, 0, len(values))
	for _, value := range values {
		var rule proto.Message
		switch v := value.(type) {
		case *bgp.FlowSpecDestinationPrefix:
			rule = &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_DST_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPAddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPAddrPrefix).Prefix.String(),
			}
		case *bgp.FlowSpecSourcePrefix:
			rule = &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_SRC_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPAddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPAddrPrefix).Prefix.String(),
			}
		case *bgp.FlowSpecDestinationPrefix6:
			rule = &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_DST_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPv6AddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPv6AddrPrefix).Prefix.String(),
				Offset:    uint32(v.Offset),
			}
		case *bgp.FlowSpecSourcePrefix6:
			rule = &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_SRC_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPv6AddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPv6AddrPrefix).Prefix.String(),
				Offset:    uint32(v.Offset),
			}
		case *bgp.FlowSpecSourceMac:
			rule = &api.FlowSpecMAC{
				Type:    uint32(bgp.FLOW_SPEC_TYPE_SRC_MAC),
				Address: v.Mac.String(),
			}
		case *bgp.FlowSpecDestinationMac:
			rule = &api.FlowSpecMAC{
				Type:    uint32(bgp.FLOW_SPEC_TYPE_DST_MAC),
				Address: v.Mac.String(),
			}
		case *bgp.FlowSpecComponent:
			items := make([]*api.FlowSpecComponentItem, 0, len(v.Items))
			for _, i := range v.Items {
				items = append(items, &api.FlowSpecComponentItem{
					Op:    uint32(i.Op),
					Value: i.Value,
				})
			}
			rule = &api.FlowSpecComponent{
				Type:  uint32(v.Type()),
				Items: items,
			}
		}
		a, _ := apb.New(rule)
		rules = append(rules, a)
	}
	return rules, nil
}

func UnmarshalFlowSpecRules(values []*apb.Any) ([]bgp.FlowSpecComponentInterface, error) {
	rules := make([]bgp.FlowSpecComponentInterface, 0, len(values))
	for _, an := range values {
		var rule bgp.FlowSpecComponentInterface
		value, err := an.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal flow spec component: %s", err)
		}
		switch v := value.(type) {
		case *api.FlowSpecIPPrefix:
			typ := bgp.BGPFlowSpecType(v.Type)
			isIPv4 := net.ParseIP(v.Prefix).To4() != nil
			switch {
			case typ == bgp.FLOW_SPEC_TYPE_DST_PREFIX && isIPv4:
				rule = bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(uint8(v.PrefixLen), v.Prefix))
			case typ == bgp.FLOW_SPEC_TYPE_SRC_PREFIX && isIPv4:
				rule = bgp.NewFlowSpecSourcePrefix(bgp.NewIPAddrPrefix(uint8(v.PrefixLen), v.Prefix))
			case typ == bgp.FLOW_SPEC_TYPE_DST_PREFIX && !isIPv4:
				rule = bgp.NewFlowSpecDestinationPrefix6(bgp.NewIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix), uint8(v.Offset))
			case typ == bgp.FLOW_SPEC_TYPE_SRC_PREFIX && !isIPv4:
				rule = bgp.NewFlowSpecSourcePrefix6(bgp.NewIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix), uint8(v.Offset))
			}
		case *api.FlowSpecMAC:
			typ := bgp.BGPFlowSpecType(v.Type)
			mac, err := net.ParseMAC(v.Address)
			if err != nil {
				return nil, fmt.Errorf("invalid mac address for %s flow spec component: %s", typ.String(), v.Address)
			}
			switch typ {
			case bgp.FLOW_SPEC_TYPE_SRC_MAC:
				rule = bgp.NewFlowSpecSourceMac(mac)
			case bgp.FLOW_SPEC_TYPE_DST_MAC:
				rule = bgp.NewFlowSpecDestinationMac(mac)
			}
		case *api.FlowSpecComponent:
			items := make([]*bgp.FlowSpecComponentItem, 0, len(v.Items))
			for _, item := range v.Items {
				items = append(items, bgp.NewFlowSpecComponentItem(uint8(item.Op), item.Value))
			}
			rule = bgp.NewFlowSpecComponent(bgp.BGPFlowSpecType(v.Type), items)
		}
		if rule == nil {
			return nil, fmt.Errorf("invalid flow spec component: %v", value)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func MarshalLsNodeDescriptor(d *bgp.LsNodeDescriptor) (*api.LsNodeDescriptor, error) {
	return &api.LsNodeDescriptor{
		Asn:         d.Asn,
		BgpLsId:     d.BGPLsID,
		OspfAreaId:  d.OspfAreaID,
		Pseudonode:  d.PseudoNode,
		IgpRouterId: d.IGPRouterID,
	}, nil
}

func MarshalLsLinkDescriptor(n *bgp.LsLinkDescriptor) (*api.LsLinkDescriptor, error) {
	return &api.LsLinkDescriptor{
		LinkLocalId:       uint32OrDefault(n.LinkLocalID),
		LinkRemoteId:      uint32OrDefault(n.LinkRemoteID),
		InterfaceAddrIpv4: ipOrDefault(n.InterfaceAddrIPv4),
		NeighborAddrIpv4:  ipOrDefault(n.NeighborAddrIPv4),
		InterfaceAddrIpv6: ipOrDefault(n.InterfaceAddrIPv6),
		NeighborAddrIpv6:  ipOrDefault(n.NeighborAddrIPv6),
	}, nil
}

func MarshalLsPrefixDescriptor(d *bgp.LsPrefixDescriptor) (*api.LsPrefixDescriptor, error) {
	p := &api.LsPrefixDescriptor{
		OspfRouteType: api.LsOspfRouteType(d.OSPFRouteType),
	}

	for _, ip := range d.IPReachability {
		p.IpReachability = append(p.IpReachability, ip.String())
	}
	return p, nil
}

func MarshalLsNodeNLRI(n *bgp.LsNodeNLRI) (*apb.Any, error) {
	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}
	node := &api.LsNodeNLRI{
		LocalNode: ln,
	}
	a, _ := apb.New(node)

	return a, nil
}

func MarshalLsLinkNLRI(n *bgp.LsLinkNLRI) (*apb.Any, error) {
	desc := &bgp.LsLinkDescriptor{}
	desc.ParseTLVs(n.LinkDesc)

	var err error
	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}
	rn, err := MarshalLsNodeDescriptor(n.RemoteNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}

	ld, err := MarshalLsLinkDescriptor(desc)
	if err != nil {
		return nil, err
	}

	link := &api.LsLinkNLRI{
		LocalNode:      ln,
		RemoteNode:     rn,
		LinkDescriptor: ld,
	}
	a, _ := apb.New(link)

	return a, nil
}

func MarshalLsPrefixV4NLRI(n *bgp.LsPrefixV4NLRI) (*apb.Any, error) {
	desc := &bgp.LsPrefixDescriptor{}
	desc.ParseTLVs(n.PrefixDesc, false)

	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}

	pd, err := MarshalLsPrefixDescriptor(desc)
	if err != nil {
		return nil, err
	}

	prefix := &api.LsPrefixV4NLRI{
		LocalNode:        ln,
		PrefixDescriptor: pd,
	}
	a, _ := apb.New(prefix)

	return a, nil
}

func MarshalLsPrefixV6NLRI(n *bgp.LsPrefixV6NLRI) (*apb.Any, error) {
	desc := &bgp.LsPrefixDescriptor{}
	desc.ParseTLVs(n.PrefixDesc, true)

	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}

	pd, err := MarshalLsPrefixDescriptor(desc)
	if err != nil {
		return nil, err
	}

	prefix := &api.LsPrefixV6NLRI{
		LocalNode:        ln,
		PrefixDescriptor: pd,
	}
	a, _ := apb.New(prefix)

	return a, nil
}

func MarshalNLRI(value bgp.AddrPrefixInterface) (*apb.Any, error) {
	var nlri proto.Message

	switch v := value.(type) {
	case *bgp.IPAddrPrefix:
		nlri = &api.IPAddressPrefix{
			PrefixLen: uint32(v.Length),
			Prefix:    v.Prefix.String(),
		}
	case *bgp.IPv6AddrPrefix:
		nlri = &api.IPAddressPrefix{
			PrefixLen: uint32(v.Length),
			Prefix:    v.Prefix.String(),
		}
	case *bgp.LabeledIPAddrPrefix:
		nlri = &api.LabeledIPAddressPrefix{
			Labels:    v.Labels.Labels,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}
	case *bgp.LabeledIPv6AddrPrefix:
		nlri = &api.LabeledIPAddressPrefix{
			Labels:    v.Labels.Labels,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}
	case *bgp.EncapNLRI:
		nlri = &api.EncapsulationNLRI{
			Address: v.String(),
		}
	case *bgp.Encapv6NLRI:
		nlri = &api.EncapsulationNLRI{
			Address: v.String(),
		}
	case *bgp.EVPNNLRI:
		switch r := v.RouteTypeData.(type) {
		case *bgp.EVPNEthernetAutoDiscoveryRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}

			nlri = &api.EVPNEthernetAutoDiscoveryRoute{
				Rd:          rd,
				Esi:         esi,
				EthernetTag: r.ETag,
				Label:       r.Label,
			}
		case *bgp.EVPNMacIPAdvertisementRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}

			nlri = &api.EVPNMACIPAdvertisementRoute{
				Rd:          rd,
				Esi:         esi,
				EthernetTag: r.ETag,
				MacAddress:  r.MacAddress.String(),
				IpAddress:   r.IPAddress.String(),
				Labels:      r.Labels,
			}
		case *bgp.EVPNMulticastEthernetTagRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri = &api.EVPNInclusiveMulticastEthernetTagRoute{
				Rd:          rd,
				EthernetTag: r.ETag,
				IpAddress:   r.IPAddress.String(),
			}
		case *bgp.EVPNEthernetSegmentRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}
			nlri = &api.EVPNEthernetSegmentRoute{
				Rd:        rd,
				Esi:       esi,
				IpAddress: r.IPAddress.String(),
			}
		case *bgp.EVPNIPPrefixRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}
			nlri = &api.EVPNIPPrefixRoute{
				Rd:          rd,
				Esi:         esi,
				EthernetTag: r.ETag,
				IpPrefix:    r.IPPrefix.String(),
				IpPrefixLen: uint32(r.IPPrefixLength),
				Label:       r.Label,
				GwAddress:   r.GWIPAddress.String(),
			}
		}
	case *bgp.LabeledVPNIPAddrPrefix:
		rd, err := MarshalRD(v.RD)
		if err != nil {
			return nil, err
		}
		nlri = &api.LabeledVPNIPAddressPrefix{
			Labels:    v.Labels.Labels,
			Rd:        rd,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}
	case *bgp.LabeledVPNIPv6AddrPrefix:
		rd, err := MarshalRD(v.RD)
		if err != nil {
			return nil, err
		}
		nlri = &api.LabeledVPNIPAddressPrefix{
			Labels:    v.Labels.Labels,
			Rd:        rd,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}
	case *bgp.RouteTargetMembershipNLRI:
		rt, err := MarshalRT(v.RouteTarget)
		if err != nil {
			return nil, err
		}
		nlri = &api.RouteTargetMembershipNLRI{
			Asn: v.AS,
			Rt:  rt,
		}
	case *bgp.FlowSpecIPv4Unicast:
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri = &api.FlowSpecNLRI{
			Rules: rules,
		}
	case *bgp.FlowSpecIPv6Unicast:
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri = &api.FlowSpecNLRI{
			Rules: rules,
		}
	case *bgp.FlowSpecIPv4VPN:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri = &api.VPNFlowSpecNLRI{
			Rd:    rd,
			Rules: rules,
		}
	case *bgp.FlowSpecIPv6VPN:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri = &api.VPNFlowSpecNLRI{
			Rd:    rd,
			Rules: rules,
		}
	case *bgp.FlowSpecL2VPN:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri = &api.VPNFlowSpecNLRI{
			Rd:    rd,
			Rules: rules,
		}
	case *bgp.LsAddrPrefix:
		switch n := v.NLRI.(type) {
		case *bgp.LsNodeNLRI:
			node, err := MarshalLsNodeNLRI(n)
			if err != nil {
				return nil, err
			}
			nlri = &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_NODE,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}

		case *bgp.LsLinkNLRI:
			node, err := MarshalLsLinkNLRI(n)
			if err != nil {
				return nil, err
			}
			nlri = &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_LINK,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}

		case *bgp.LsPrefixV4NLRI:
			node, err := MarshalLsPrefixV4NLRI(n)
			if err != nil {
				return nil, err
			}
			nlri = &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_PREFIX_V4,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}

		case *bgp.LsPrefixV6NLRI:
			node, err := MarshalLsPrefixV6NLRI(n)
			if err != nil {
				return nil, err
			}
			nlri = &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_PREFIX_V6,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}
		}
	case *bgp.SRPolicyIPv4:
		nlri = &api.SRPolicyNLRI{
			Length:        uint32(v.Length),
			Distinguisher: v.Distinguisher,
			Color:         v.Color,
			Endpoint:      v.Endpoint,
		}
	case *bgp.SRPolicyIPv6:
		nlri = &api.SRPolicyNLRI{
			Length:        uint32(v.Length),
			Distinguisher: v.Distinguisher,
			Color:         v.Color,
			Endpoint:      v.Endpoint,
		}
	case *bgp.MUPNLRI:
		switch r := v.RouteTypeData.(type) {
		case *bgp.MUPInterworkSegmentDiscoveryRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri = &api.MUPInterworkSegmentDiscoveryRoute{
				Rd:           rd,
				PrefixLength: uint32(r.PrefixLength),
				Prefix:       r.Prefix.String(),
			}
		case *bgp.MUPDirectSegmentDiscoveryRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri = &api.MUPDirectSegmentDiscoveryRoute{
				Rd:      rd,
				Address: r.Address.String(),
			}
		case *bgp.MUPType1SessionTransformedRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri = &api.MUPType1SessionTransformedRoute{
				Rd:                    rd,
				Prefix:                r.Prefix.String(),
				Teid:                  r.TEID,
				Qfi:                   uint32(r.QFI),
				EndpointAddressLength: uint32(r.EndpointAddressLength),
				EndpointAddress:       r.EndpointAddress.String(),
			}
		case *bgp.MUPType2SessionTransformedRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri = &api.MUPType2SessionTransformedRoute{
				Rd:                    rd,
				EndpointAddressLength: uint32(r.EndpointAddressLength),
				EndpointAddress:       r.EndpointAddress.String(),
				Teid:                  r.TEID,
			}
		}
	}

	an, _ := apb.New(nlri)
	return an, nil
}

func MarshalNLRIs(values []bgp.AddrPrefixInterface) ([]*apb.Any, error) {
	nlris := make([]*apb.Any, 0, len(values))
	for _, value := range values {
		nlri, err := MarshalNLRI(value)
		if err != nil {
			return nil, err
		}
		nlris = append(nlris, nlri)
	}
	return nlris, nil
}

func UnmarshalNLRI(rf bgp.RouteFamily, an *apb.Any) (bgp.AddrPrefixInterface, error) {
	var nlri bgp.AddrPrefixInterface

	value, err := an.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal nlri: %s", err)
	}

	switch v := value.(type) {
	case *api.IPAddressPrefix:
		switch rf {
		case bgp.RF_IPv4_UC:
			nlri = bgp.NewIPAddrPrefix(uint8(v.PrefixLen), v.Prefix)
		case bgp.RF_IPv6_UC:
			nlri = bgp.NewIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix)
		}
	case *api.LabeledIPAddressPrefix:
		switch rf {
		case bgp.RF_IPv4_MPLS:
			nlri = bgp.NewLabeledIPAddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...))
		case bgp.RF_IPv6_MPLS:
			nlri = bgp.NewLabeledIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...))
		}
	case *api.EncapsulationNLRI:
		switch rf {
		case bgp.RF_IPv4_ENCAP:
			nlri = bgp.NewEncapNLRI(v.Address)
		case bgp.RF_IPv6_ENCAP:
			nlri = bgp.NewEncapv6NLRI(v.Address)
		}
	case *api.EVPNEthernetAutoDiscoveryRoute:
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNEthernetAutoDiscoveryRoute(rd, *esi, v.EthernetTag, v.Label)
		}
	case *api.EVPNMACIPAdvertisementRoute:
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNMacIPAdvertisementRoute(rd, *esi, v.EthernetTag, v.MacAddress, v.IpAddress, v.Labels)
		}
	case *api.EVPNInclusiveMulticastEthernetTagRoute:
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNMulticastEthernetTagRoute(rd, v.EthernetTag, v.IpAddress)
		}
	case *api.EVPNEthernetSegmentRoute:
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNEthernetSegmentRoute(rd, *esi, v.IpAddress)
		}
	case *api.EVPNIPPrefixRoute:
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNIPPrefixRoute(rd, *esi, v.EthernetTag, uint8(v.IpPrefixLen), v.IpPrefix, v.GwAddress, v.Label)
		}
	case *api.SRPolicyNLRI:
		switch rf {
		case bgp.RF_SR_POLICY_IPv4:
			nlri = bgp.NewSRPolicyIPv4(v.Length, v.Distinguisher, v.Color, v.Endpoint)
		case bgp.RF_SR_POLICY_IPv6:
			nlri = bgp.NewSRPolicyIPv6(v.Length, v.Distinguisher, v.Color, v.Endpoint)
		}
	case *api.LabeledVPNIPAddressPrefix:
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		switch rf {
		case bgp.RF_IPv4_VPN:
			nlri = bgp.NewLabeledVPNIPAddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...), rd)
		case bgp.RF_IPv6_VPN:
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...), rd)
		}
	case *api.RouteTargetMembershipNLRI:
		rt, err := UnmarshalRT(v.Rt)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewRouteTargetMembershipNLRI(v.Asn, rt)
	case *api.FlowSpecNLRI:
		rules, err := UnmarshalFlowSpecRules(v.Rules)
		if err != nil {
			return nil, err
		}
		switch rf {
		case bgp.RF_FS_IPv4_UC:
			nlri = bgp.NewFlowSpecIPv4Unicast(rules)
		case bgp.RF_FS_IPv6_UC:
			nlri = bgp.NewFlowSpecIPv6Unicast(rules)
		}
	case *api.VPNFlowSpecNLRI:
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		rules, err := UnmarshalFlowSpecRules(v.Rules)
		if err != nil {
			return nil, err
		}
		switch rf {
		case bgp.RF_FS_IPv4_VPN:
			nlri = bgp.NewFlowSpecIPv4VPN(rd, rules)
		case bgp.RF_FS_IPv6_VPN:
			nlri = bgp.NewFlowSpecIPv6VPN(rd, rules)
		case bgp.RF_FS_L2_VPN:
			nlri = bgp.NewFlowSpecL2VPN(rd, rules)
		}
	case *api.MUPInterworkSegmentDiscoveryRoute:
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(v.Prefix)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewMUPInterworkSegmentDiscoveryRoute(rd, prefix)
	case *api.MUPDirectSegmentDiscoveryRoute:
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(v.Address)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewMUPDirectSegmentDiscoveryRoute(rd, address)
	case *api.MUPType1SessionTransformedRoute:
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(v.Prefix)
		if err != nil {
			return nil, err
		}
		ea, err := netip.ParseAddr(v.EndpointAddress)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewMUPType1SessionTransformedRoute(rd, prefix, v.Teid, uint8(v.Qfi), ea)
	case *api.MUPType2SessionTransformedRoute:
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		ea, err := netip.ParseAddr(v.EndpointAddress)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewMUPType2SessionTransformedRoute(rd, ea, v.Teid)
	}

	if nlri == nil {
		return nil, fmt.Errorf("invalid nlri for %s family: %s", rf.String(), value)
	}

	return nlri, nil
}

func UnmarshalNLRIs(rf bgp.RouteFamily, values []*apb.Any) ([]bgp.AddrPrefixInterface, error) {
	nlris := make([]bgp.AddrPrefixInterface, 0, len(values))
	for _, an := range values {
		nlri, err := UnmarshalNLRI(rf, an)
		if err != nil {
			return nil, err
		}
		nlris = append(nlris, nlri)
	}
	return nlris, nil
}

func NewMpReachNLRIAttributeFromNative(a *bgp.PathAttributeMpReachNLRI) (*api.MpReachNLRIAttribute, error) {
	var nexthops []string
	if a.SAFI == bgp.SAFI_FLOW_SPEC_UNICAST || a.SAFI == bgp.SAFI_FLOW_SPEC_VPN {
		nexthops = nil
	} else {
		nexthops = []string{a.Nexthop.String()}
		if a.LinkLocalNexthop != nil && a.LinkLocalNexthop.IsLinkLocalUnicast() {
			nexthops = append(nexthops, a.LinkLocalNexthop.String())
		}
	}
	n, err := MarshalNLRIs(a.Value)
	if err != nil {
		return nil, err
	}
	return &api.MpReachNLRIAttribute{
		Family:   ToApiFamily(a.AFI, a.SAFI),
		NextHops: nexthops,
		Nlris:    n,
	}, nil
}

func NewMpUnreachNLRIAttributeFromNative(a *bgp.PathAttributeMpUnreachNLRI) (*api.MpUnreachNLRIAttribute, error) {
	n, err := MarshalNLRIs(a.Value)
	if err != nil {
		return nil, err
	}
	return &api.MpUnreachNLRIAttribute{
		Family: ToApiFamily(a.AFI, a.SAFI),
		Nlris:  n,
	}, nil
}

func MarshalRT(rt bgp.ExtendedCommunityInterface) (*apb.Any, error) {
	var r proto.Message
	switch v := rt.(type) {
	case *bgp.TwoOctetAsSpecificExtended:
		r = &api.TwoOctetAsSpecificExtended{
			IsTransitive: true,
			SubType:      uint32(bgp.EC_SUBTYPE_ROUTE_TARGET),
			Asn:          uint32(v.AS),
			LocalAdmin:   uint32(v.LocalAdmin),
		}
	case *bgp.IPv4AddressSpecificExtended:
		r = &api.IPv4AddressSpecificExtended{
			IsTransitive: true,
			SubType:      uint32(bgp.EC_SUBTYPE_ROUTE_TARGET),
			Address:      v.IPv4.String(),
			LocalAdmin:   uint32(v.LocalAdmin),
		}
	case *bgp.FourOctetAsSpecificExtended:
		r = &api.FourOctetAsSpecificExtended{
			IsTransitive: true,
			SubType:      uint32(bgp.EC_SUBTYPE_ROUTE_TARGET),
			Asn:          uint32(v.AS),
			LocalAdmin:   uint32(v.LocalAdmin),
		}
	default:
		return nil, fmt.Errorf("invalid rt type to marshal: %v", rt)
	}
	a, _ := apb.New(r)
	return a, nil
}

func MarshalRTs(values []bgp.ExtendedCommunityInterface) ([]*apb.Any, error) {
	rts := make([]*apb.Any, 0, len(values))
	for _, rt := range values {
		r, err := MarshalRT(rt)
		if err != nil {
			return nil, err
		}
		rts = append(rts, r)
	}
	return rts, nil
}

func UnmarshalRT(a *apb.Any) (bgp.ExtendedCommunityInterface, error) {
	value, err := a.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal route target: %s", err)
	}
	switch v := value.(type) {
	case *api.TwoOctetAsSpecificExtended:
		return bgp.NewTwoOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), uint16(v.Asn), v.LocalAdmin, v.IsTransitive), nil
	case *api.IPv4AddressSpecificExtended:
		rt := bgp.NewIPv4AddressSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Address, uint16(v.LocalAdmin), v.IsTransitive)
		if rt == nil {
			return nil, fmt.Errorf("invalid address for ipv4 address specific route target: %s", v.Address)
		}
		return rt, nil
	case *api.FourOctetAsSpecificExtended:
		return bgp.NewFourOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Asn, uint16(v.LocalAdmin), v.IsTransitive), nil
	}
	return nil, fmt.Errorf("invalid route target type: %s", a.TypeUrl)
}

func UnmarshalRTs(values []*apb.Any) ([]bgp.ExtendedCommunityInterface, error) {
	rts := make([]bgp.ExtendedCommunityInterface, 0, len(values))
	for _, an := range values {
		rt, err := UnmarshalRT(an)
		if err != nil {
			return nil, err
		}
		rts = append(rts, rt)
	}
	return rts, nil
}

func NewExtendedCommunitiesAttributeFromNative(a *bgp.PathAttributeExtendedCommunities) (*api.ExtendedCommunitiesAttribute, error) {
	communities := make([]*apb.Any, 0, len(a.Value))
	for _, value := range a.Value {
		var community proto.Message
		switch v := value.(type) {
		case *bgp.TwoOctetAsSpecificExtended:
			community = &api.TwoOctetAsSpecificExtended{
				IsTransitive: v.IsTransitive,
				SubType:      uint32(v.SubType),
				Asn:          uint32(v.AS),
				LocalAdmin:   uint32(v.LocalAdmin),
			}
		case *bgp.IPv4AddressSpecificExtended:
			community = &api.IPv4AddressSpecificExtended{
				IsTransitive: v.IsTransitive,
				SubType:      uint32(v.SubType),
				Address:      v.IPv4.String(),
				LocalAdmin:   uint32(v.LocalAdmin),
			}
		case *bgp.FourOctetAsSpecificExtended:
			community = &api.FourOctetAsSpecificExtended{
				IsTransitive: v.IsTransitive,
				SubType:      uint32(v.SubType),
				Asn:          uint32(v.AS),
				LocalAdmin:   uint32(v.LocalAdmin),
			}
		case *bgp.ValidationExtended:
			community = &api.ValidationExtended{
				State: uint32(v.State),
			}
		case *bgp.LinkBandwidthExtended:
			community = &api.LinkBandwidthExtended{
				Asn:       uint32(v.AS),
				Bandwidth: v.Bandwidth,
			}
		case *bgp.ColorExtended:
			community = &api.ColorExtended{
				Color: v.Color,
			}
		case *bgp.EncapExtended:
			community = &api.EncapExtended{
				TunnelType: uint32(v.TunnelType),
			}
		case *bgp.DefaultGatewayExtended:
			community = &api.DefaultGatewayExtended{}
		case *bgp.OpaqueExtended:
			community = &api.OpaqueExtended{
				IsTransitive: v.IsTransitive,
				Value:        v.Value,
			}
		case *bgp.ESILabelExtended:
			community = &api.ESILabelExtended{
				IsSingleActive: v.IsSingleActive,
				Label:          v.Label,
			}
		case *bgp.ESImportRouteTarget:
			community = &api.ESImportRouteTarget{
				EsImport: v.ESImport.String(),
			}
		case *bgp.MacMobilityExtended:
			community = &api.MacMobilityExtended{
				IsSticky:    v.IsSticky,
				SequenceNum: v.Sequence,
			}
		case *bgp.RouterMacExtended:
			community = &api.RouterMacExtended{
				Mac: v.Mac.String(),
			}
		case *bgp.TrafficRateExtended:
			community = &api.TrafficRateExtended{
				Asn:  uint32(v.AS),
				Rate: v.Rate,
			}
		case *bgp.TrafficActionExtended:
			community = &api.TrafficActionExtended{
				Terminal: v.Terminal,
				Sample:   v.Sample,
			}
		case *bgp.RedirectTwoOctetAsSpecificExtended:
			community = &api.RedirectTwoOctetAsSpecificExtended{
				Asn:        uint32(v.AS),
				LocalAdmin: v.LocalAdmin,
			}
		case *bgp.RedirectIPv4AddressSpecificExtended:
			community = &api.RedirectIPv4AddressSpecificExtended{
				Address:    v.IPv4.String(),
				LocalAdmin: uint32(v.LocalAdmin),
			}
		case *bgp.RedirectFourOctetAsSpecificExtended:
			community = &api.RedirectFourOctetAsSpecificExtended{
				Asn:        v.AS,
				LocalAdmin: uint32(v.LocalAdmin),
			}
		case *bgp.TrafficRemarkExtended:
			community = &api.TrafficRemarkExtended{
				Dscp: uint32(v.DSCP),
			}
		case *bgp.MUPExtended:
			community = &api.MUPExtended{
				SubType:    uint32(v.SubType),
				SegmentId2: uint32(v.SegmentID2),
				SegmentId4: v.SegmentID4,
			}
		case *bgp.UnknownExtended:
			community = &api.UnknownExtended{
				Type:  uint32(v.Type),
				Value: v.Value,
			}
		default:
			return nil, fmt.Errorf("unsupported extended community: %v", value)
		}
		an, _ := apb.New(community)
		communities = append(communities, an)
	}
	return &api.ExtendedCommunitiesAttribute{
		Communities: communities,
	}, nil
}

func unmarshalExComm(a *api.ExtendedCommunitiesAttribute) (*bgp.PathAttributeExtendedCommunities, error) {
	communities := make([]bgp.ExtendedCommunityInterface, 0, len(a.Communities))
	for _, an := range a.Communities {
		var community bgp.ExtendedCommunityInterface
		value, err := an.UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal extended community: %s", err)
		}
		switch v := value.(type) {
		case *api.TwoOctetAsSpecificExtended:
			community = bgp.NewTwoOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), uint16(v.Asn), v.LocalAdmin, v.IsTransitive)
		case *api.IPv4AddressSpecificExtended:
			community = bgp.NewIPv4AddressSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Address, uint16(v.LocalAdmin), v.IsTransitive)
		case *api.FourOctetAsSpecificExtended:
			community = bgp.NewFourOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Asn, uint16(v.LocalAdmin), v.IsTransitive)
		case *api.ValidationExtended:
			community = bgp.NewValidationExtended(bgp.ValidationState(v.State))
		case *api.LinkBandwidthExtended:
			community = bgp.NewLinkBandwidthExtended(uint16(v.Asn), v.Bandwidth)
		case *api.ColorExtended:
			community = bgp.NewColorExtended(v.Color)
		case *api.EncapExtended:
			community = bgp.NewEncapExtended(bgp.TunnelType(v.TunnelType))
		case *api.DefaultGatewayExtended:
			community = bgp.NewDefaultGatewayExtended()
		case *api.OpaqueExtended:
			community = bgp.NewOpaqueExtended(v.IsTransitive, v.Value)
		case *api.ESILabelExtended:
			community = bgp.NewESILabelExtended(v.Label, v.IsSingleActive)
		case *api.ESImportRouteTarget:
			community = bgp.NewESImportRouteTarget(v.EsImport)
		case *api.MacMobilityExtended:
			community = bgp.NewMacMobilityExtended(v.SequenceNum, v.IsSticky)
		case *api.RouterMacExtended:
			community = bgp.NewRoutersMacExtended(v.Mac)
		case *api.TrafficRateExtended:
			community = bgp.NewTrafficRateExtended(uint16(v.Asn), v.Rate)
		case *api.TrafficActionExtended:
			community = bgp.NewTrafficActionExtended(v.Terminal, v.Sample)
		case *api.RedirectTwoOctetAsSpecificExtended:
			community = bgp.NewRedirectTwoOctetAsSpecificExtended(uint16(v.Asn), v.LocalAdmin)
		case *api.RedirectIPv4AddressSpecificExtended:
			community = bgp.NewRedirectIPv4AddressSpecificExtended(v.Address, uint16(v.LocalAdmin))
		case *api.RedirectFourOctetAsSpecificExtended:
			community = bgp.NewRedirectFourOctetAsSpecificExtended(v.Asn, uint16(v.LocalAdmin))
		case *api.TrafficRemarkExtended:
			community = bgp.NewTrafficRemarkExtended(uint8(v.Dscp))
		case *api.MUPExtended:
			community = bgp.NewMUPExtended(uint16(v.SegmentId2), v.SegmentId4)
		case *api.UnknownExtended:
			community = bgp.NewUnknownExtended(bgp.ExtendedCommunityAttrType(v.Type), v.Value)
		}
		if community == nil {
			return nil, fmt.Errorf("invalid extended community: %v", value)
		}
		communities = append(communities, community)
	}
	return bgp.NewPathAttributeExtendedCommunities(communities), nil
}

func NewAs4PathAttributeFromNative(a *bgp.PathAttributeAs4Path) (*api.As4PathAttribute, error) {
	segments := make([]*api.AsSegment, 0, len(a.Value))
	for _, param := range a.Value {
		segments = append(segments, &api.AsSegment{
			Type:    api.AsSegment_Type(param.Type),
			Numbers: param.AS,
		})
	}
	return &api.As4PathAttribute{
		Segments: segments,
	}, nil
}

func NewAs4AggregatorAttributeFromNative(a *bgp.PathAttributeAs4Aggregator) (*api.As4AggregatorAttribute, error) {
	return &api.As4AggregatorAttribute{
		Asn:     a.Value.AS,
		Address: a.Value.Address.String(),
	}, nil
}

func NewPmsiTunnelAttributeFromNative(a *bgp.PathAttributePmsiTunnel) (*api.PmsiTunnelAttribute, error) {
	var flags uint32
	if a.IsLeafInfoRequired {
		flags |= 0x01
	}
	id, _ := a.TunnelID.Serialize()
	return &api.PmsiTunnelAttribute{
		Flags: flags,
		Type:  uint32(a.TunnelType),
		Label: a.Label,
		Id:    id,
	}, nil
}

func NewTunnelEncapAttributeFromNative(a *bgp.PathAttributeTunnelEncap) (*api.TunnelEncapAttribute, error) {
	tlvs := make([]*api.TunnelEncapTLV, 0, len(a.Value))
	for _, v := range a.Value {
		subTlvs := make([]*apb.Any, 0, len(v.Value))
		for _, s := range v.Value {
			var subTlv proto.Message
			switch sv := s.(type) {
			case *bgp.TunnelEncapSubTLVEncapsulation:
				subTlv = &api.TunnelEncapSubTLVEncapsulation{
					Key:    sv.Key,
					Cookie: sv.Cookie,
				}
			case *bgp.TunnelEncapSubTLVProtocol:
				subTlv = &api.TunnelEncapSubTLVProtocol{
					Protocol: uint32(sv.Protocol),
				}
			case *bgp.TunnelEncapSubTLVColor:
				subTlv = &api.TunnelEncapSubTLVColor{
					Color: sv.Color,
				}
			case *bgp.TunnelEncapSubTLVEgressEndpoint:
				subTlv = &api.TunnelEncapSubTLVEgressEndpoint{
					Address: sv.Address.String(),
				}
			case *bgp.TunnelEncapSubTLVUDPDestPort:
				subTlv = &api.TunnelEncapSubTLVUDPDestPort{
					Port: uint32(sv.UDPDestPort),
				}
			case *bgp.TunnelEncapSubTLVUnknown:
				subTlv = &api.TunnelEncapSubTLVUnknown{
					Type:  uint32(sv.Type),
					Value: sv.Value,
				}
			case *bgp.TunnelEncapSubTLVSRBSID:
				t, err := MarshalSRBSID(sv)
				if err != nil {
					return nil, err
				}
				subTlv = t
				// TODO (sbezverk) Add processing of SRv6 Binding SID when it gets assigned ID
			case *bgp.TunnelEncapSubTLVSRCandidatePathName:
				subTlv = &api.TunnelEncapSubTLVSRCandidatePathName{
					CandidatePathName: sv.CandidatePathName,
				}
				// TODO (sbezverk) Add processing of SR Policy name when it gets assigned ID
			case *bgp.TunnelEncapSubTLVSRENLP:
				subTlv = &api.TunnelEncapSubTLVSRENLP{
					Flags: uint32(sv.Flags),
					Enlp:  api.ENLPType(sv.ENLP),
				}
			case *bgp.TunnelEncapSubTLVSRPreference:
				subTlv = &api.TunnelEncapSubTLVSRPreference{
					Flags:      uint32(sv.Flags),
					Preference: sv.Preference,
				}
			case *bgp.TunnelEncapSubTLVSRPriority:
				subTlv = &api.TunnelEncapSubTLVSRPriority{
					Priority: uint32(sv.Priority),
				}
			case *bgp.TunnelEncapSubTLVSRSegmentList:
				s, err := MarshalSRSegments(sv.Segments)
				if err != nil {
					return nil, err
				}
				subTlv = &api.TunnelEncapSubTLVSRSegmentList{
					Weight: &api.SRWeight{
						Flags:  uint32(sv.Weight.Flags),
						Weight: uint32(sv.Weight.Weight),
					},
					Segments: s,
				}
			}
			an, _ := apb.New(subTlv)
			subTlvs = append(subTlvs, an)
		}
		tlvs = append(tlvs, &api.TunnelEncapTLV{
			Type: uint32(v.Type),
			Tlvs: subTlvs,
		})
	}
	return &api.TunnelEncapAttribute{
		Tlvs: tlvs,
	}, nil
}

func NewIP6ExtendedCommunitiesAttributeFromNative(a *bgp.PathAttributeIP6ExtendedCommunities) (*api.IP6ExtendedCommunitiesAttribute, error) {
	communities := make([]*apb.Any, 0, len(a.Value))
	for _, value := range a.Value {
		var community proto.Message
		switch v := value.(type) {
		case *bgp.IPv6AddressSpecificExtended:
			community = &api.IPv6AddressSpecificExtended{
				IsTransitive: v.IsTransitive,
				SubType:      uint32(v.SubType),
				Address:      v.IPv6.String(),
				LocalAdmin:   uint32(v.LocalAdmin),
			}
		case *bgp.RedirectIPv6AddressSpecificExtended:
			community = &api.RedirectIPv6AddressSpecificExtended{
				Address:    v.IPv6.String(),
				LocalAdmin: uint32(v.LocalAdmin),
			}
		default:
			return nil, fmt.Errorf("invalid ipv6 extended community: %v", value)
		}
		an, _ := apb.New(community)
		communities = append(communities, an)
	}
	return &api.IP6ExtendedCommunitiesAttribute{
		Communities: communities,
	}, nil
}

func NewAigpAttributeFromNative(a *bgp.PathAttributeAigp) (*api.AigpAttribute, error) {
	tlvs := make([]*apb.Any, 0, len(a.Values))
	for _, value := range a.Values {
		var tlv proto.Message
		switch v := value.(type) {
		case *bgp.AigpTLVIgpMetric:
			tlv = &api.AigpTLVIGPMetric{
				Metric: v.Metric,
			}
		case *bgp.AigpTLVDefault:
			tlv = &api.AigpTLVUnknown{
				Type:  uint32(v.Type()),
				Value: v.Value,
			}
		}
		an, _ := apb.New(tlv)
		tlvs = append(tlvs, an)
	}
	return &api.AigpAttribute{
		Tlvs: tlvs,
	}, nil
}

func NewLargeCommunitiesAttributeFromNative(a *bgp.PathAttributeLargeCommunities) (*api.LargeCommunitiesAttribute, error) {
	communities := make([]*api.LargeCommunity, 0, len(a.Values))
	for _, v := range a.Values {
		communities = append(communities, &api.LargeCommunity{
			GlobalAdmin: v.ASN,
			LocalData1:  v.LocalData1,
			LocalData2:  v.LocalData2,
		})
	}
	return &api.LargeCommunitiesAttribute{
		Communities: communities,
	}, nil
}

func stringOrDefault(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func bytesOrDefault(b *[]byte) []byte {
	if b == nil {
		return []byte{}
	}
	return *b
}

func ipOrDefault(ip *net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func uint32OrDefault(i *uint32) uint32 {
	if i == nil {
		return 0
	}
	return *i
}

func float32OrDefault(f *float32) float32 {
	if f == nil {
		return 0.0
	}
	return *f
}

func NewLsAttributeFromNative(a *bgp.PathAttributeLs) (*api.LsAttribute, error) {
	attr := a.Extract()

	apiAttr := &api.LsAttribute{
		Node: &api.LsAttributeNode{
			Name:            stringOrDefault(attr.Node.Name),
			Opaque:          bytesOrDefault(attr.Node.Opaque),
			IsisArea:        bytesOrDefault(attr.Node.IsisArea),
			LocalRouterId:   ipOrDefault(attr.Node.LocalRouterID),
			LocalRouterIdV6: ipOrDefault(attr.Node.LocalRouterIDv6),

			SrAlgorithms: bytesOrDefault(attr.Node.SrAlgorithms),
		},
		Link: &api.LsAttributeLink{
			Name:             stringOrDefault(attr.Link.Name),
			Opaque:           bytesOrDefault(attr.Link.Opaque),
			LocalRouterId:    ipOrDefault(attr.Link.LocalRouterID),
			LocalRouterIdV6:  ipOrDefault(attr.Link.LocalRouterIDv6),
			RemoteRouterId:   ipOrDefault(attr.Link.RemoteRouterID),
			RemoteRouterIdV6: ipOrDefault(attr.Link.RemoteRouterIDv6),
			AdminGroup:       uint32OrDefault(attr.Link.AdminGroup),
			DefaultTeMetric:  uint32OrDefault(attr.Link.DefaultTEMetric),
			IgpMetric:        uint32OrDefault(attr.Link.IGPMetric),

			Bandwidth:           float32OrDefault(attr.Link.Bandwidth),
			ReservableBandwidth: float32OrDefault(attr.Link.ReservableBandwidth),
			SrAdjacencySid:      uint32OrDefault(attr.Link.SrAdjacencySID),
		},
		Prefix: &api.LsAttributePrefix{
			Opaque: bytesOrDefault(attr.Prefix.Opaque),

			SrPrefixSid: uint32OrDefault(attr.Prefix.SrPrefixSID),
		},
	}

	if attr.Node.Flags != nil {
		apiAttr.Node.Flags = &api.LsNodeFlags{
			Overload: attr.Node.Flags.Overload,
			Attached: attr.Node.Flags.Attached,
			External: attr.Node.Flags.External,
			Abr:      attr.Node.Flags.ABR,
			Router:   attr.Node.Flags.Router,
			V6:       attr.Node.Flags.V6,
		}
	}

	if attr.Node.SrCapabilties != nil {
		apiAttr.Node.SrCapabilities = &api.LsSrCapabilities{
			Ipv4Supported: attr.Node.SrCapabilties.IPv4Supported,
			Ipv6Supported: attr.Node.SrCapabilties.IPv6Supported,
		}

		for _, r := range attr.Node.SrCapabilties.Ranges {
			apiAttr.Node.SrCapabilities.Ranges = append(apiAttr.Node.SrCapabilities.Ranges, &api.LsSrRange{
				Begin: r.Begin,
				End:   r.End,
			})
		}
	}

	if attr.Node.SrLocalBlock != nil {
		apiAttr.Node.SrLocalBlock = &api.LsSrLocalBlock{}
		for _, r := range attr.Node.SrLocalBlock.Ranges {
			apiAttr.Node.SrLocalBlock.Ranges = append(apiAttr.Node.SrLocalBlock.Ranges, &api.LsSrRange{
				Begin: r.Begin,
				End:   r.End,
			})
		}
	}

	if attr.Link.UnreservedBandwidth != nil {
		for _, f := range attr.Link.UnreservedBandwidth {
			apiAttr.Link.UnreservedBandwidth = append(apiAttr.Link.UnreservedBandwidth, f)
		}
	}

	if attr.Link.Srlgs != nil {
		apiAttr.Link.Srlgs = append(apiAttr.Link.Srlgs, *attr.Link.Srlgs...)
	}

	if attr.Prefix.IGPFlags != nil {
		apiAttr.Prefix.IgpFlags = &api.LsIGPFlags{
			Down:          attr.Prefix.IGPFlags.Down,
			NoUnicast:     attr.Prefix.IGPFlags.NoUnicast,
			LocalAddress:  attr.Prefix.IGPFlags.LocalAddress,
			PropagateNssa: attr.Prefix.IGPFlags.PropagateNSSA,
		}
	}

	return apiAttr, nil
}

func NewUnknownAttributeFromNative(a *bgp.PathAttributeUnknown) (*api.UnknownAttribute, error) {
	return &api.UnknownAttribute{
		Flags: uint32(a.Flags),
		Type:  uint32(a.Type),
		Value: a.Value,
	}, nil
}

func MarshalPathAttributes(attrList []bgp.PathAttributeInterface) ([]*apb.Any, error) {
	anyList := make([]*apb.Any, 0, len(attrList))
	for _, attr := range attrList {
		switch a := attr.(type) {
		case *bgp.PathAttributeOrigin:
			v, err := NewOriginAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeAsPath:
			v, err := NewAsPathAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeNextHop:
			v, err := NewNextHopAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeMultiExitDisc:
			v, err := NewMultiExitDiscAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeLocalPref:
			v, err := NewLocalPrefAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeAtomicAggregate:
			v, err := NewAtomicAggregateAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeAggregator:
			v, err := NewAggregatorAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeCommunities:
			v, err := NewCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeOriginatorId:
			v, err := NewOriginatorIdAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeClusterList:
			v, err := NewClusterListAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeMpReachNLRI:
			v, err := NewMpReachNLRIAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeMpUnreachNLRI:
			v, err := NewMpUnreachNLRIAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeExtendedCommunities:
			v, err := NewExtendedCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeAs4Path:
			v, err := NewAs4PathAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeAs4Aggregator:
			v, err := NewAs4AggregatorAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributePmsiTunnel:
			v, err := NewPmsiTunnelAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeTunnelEncap:
			v, err := NewTunnelEncapAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeIP6ExtendedCommunities:
			v, err := NewIP6ExtendedCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeAigp:
			v, err := NewAigpAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeLargeCommunities:
			v, err := NewLargeCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeLs:
			v, err := NewLsAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributePrefixSID:
			v, err := NewPrefixSIDAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		case *bgp.PathAttributeUnknown:
			v, err := NewUnknownAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			n, _ := apb.New(v)
			anyList = append(anyList, n)
		}
	}
	return anyList, nil
}

func UnmarshalPathAttributes(values []*apb.Any) ([]bgp.PathAttributeInterface, error) {
	attrList := make([]bgp.PathAttributeInterface, 0, len(values))
	typeMap := make(map[bgp.BGPAttrType]struct{})
	for _, an := range values {
		attr, err := UnmarshalAttribute(an)
		if err != nil {
			return nil, err
		}
		if _, ok := typeMap[attr.GetType()]; ok {
			return nil, fmt.Errorf("duplicated path attribute type: %d", attr.GetType())
		}
		typeMap[attr.GetType()] = struct{}{}
		attrList = append(attrList, attr)
	}
	return attrList, nil
}

// MarshalSRBSID marshals SR Policy Binding SID Sub TLV structure
func MarshalSRBSID(bsid *bgp.TunnelEncapSubTLVSRBSID) (*apb.Any, error) {
	var r proto.Message
	s := &api.SRBindingSID{
		Sid: make([]byte, len(bsid.BSID.Value)),
	}
	copy(s.Sid, bsid.BSID.Value)
	s.SFlag = bsid.Flags&0x80 == 0x80
	s.IFlag = bsid.Flags&0x40 == 0x40
	r = s
	a, _ := apb.New(r)
	return a, nil
}

// UnmarshalSRBSID unmarshals SR Policy Binding SID Sub TLV and returns native TunnelEncapSubTLVInterface interface
func UnmarshalSRBSID(bsid *apb.Any) (bgp.TunnelEncapSubTLVInterface, error) {
	value, err := bsid.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tunnel encap sub tlv: %s", err)
	}
	switch v := value.(type) {
	case *api.SRBindingSID:
		b, err := bgp.NewBSID(v.Sid)
		if err != nil {
			return nil, err
		}
		flags := uint8(0x0)
		if v.SFlag {
			flags += 0x80
		}
		if v.IFlag {
			flags += 0x40
		}
		return &bgp.TunnelEncapSubTLVSRBSID{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
				Length: uint16(2 + b.Len()),
			},
			BSID:  b,
			Flags: flags,
		}, nil
	case *api.SRv6BindingSID:
		b, err := bgp.NewBSID(v.Sid)
		if err != nil {
			return nil, err
		}
		result := &bgp.TunnelEncapSubTLVSRv6BSID{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
				Length: uint16(2 + b.Len()),
			},
			Flags: 0,
			BSID:  b,
		}

		if v.EndpointBehaviorStructure != nil {
			result.EPBAS = &bgp.SRv6EndpointBehaviorStructure{
				Behavior: bgp.SRBehavior(v.EndpointBehaviorStructure.Behavior),
				BlockLen: uint8(v.EndpointBehaviorStructure.BlockLen),
				NodeLen:  uint8(v.EndpointBehaviorStructure.NodeLen),
				FuncLen:  uint8(v.EndpointBehaviorStructure.FuncLen),
				ArgLen:   uint8(v.EndpointBehaviorStructure.ArgLen),
			}
		}

		return result, nil
	default:
		return nil, fmt.Errorf("unknown binding sid type %+v", v)
	}
}

// MarshalSRSegments marshals a slice of SR Policy Segment List
func MarshalSRSegments(segs []bgp.TunnelEncapSubTLVInterface) ([]*apb.Any, error) {
	anyList := make([]*apb.Any, 0, len(segs))
	for _, seg := range segs {
		var r proto.Message
		switch s := seg.(type) {
		case *bgp.SegmentTypeA:
			r = &api.SegmentTypeA{
				Label: s.Label,
				Flags: &api.SegmentFlags{
					VFlag: s.Flags&0x80 == 0x80,
					AFlag: s.Flags&0x40 == 0x40,
					SFlag: s.Flags&0x20 == 0x20,
					BFlag: s.Flags&0x10 == 0x10,
				},
			}
		case *bgp.SegmentTypeB:
			flags := &api.SegmentFlags{
				VFlag: s.Flags&0x80 == 0x80,
				AFlag: s.Flags&0x40 == 0x40,
				SFlag: s.Flags&0x20 == 0x20,
				BFlag: s.Flags&0x10 == 0x10,
			}
			segment := &api.SegmentTypeB{
				Flags: flags,
				Sid:   s.SID,
			}
			if s.SRv6EBS != nil {
				segment.EndpointBehaviorStructure = &api.SRv6EndPointBehavior{
					Behavior: api.SRv6Behavior(s.SRv6EBS.Behavior),
					BlockLen: uint32(s.SRv6EBS.BlockLen),
					NodeLen:  uint32(s.SRv6EBS.NodeLen),
					FuncLen:  uint32(s.SRv6EBS.FuncLen),
					ArgLen:   uint32(s.SRv6EBS.ArgLen),
				}
			}
			r = segment
		default:
			// Unrecognize Segment type, skip it
			continue
		}
		a, _ := apb.New(r)
		anyList = append(anyList, a)
	}
	return anyList, nil
}

// UnmarshalSRSegments unmarshals SR Policy Segments slice of structs
func UnmarshalSRSegments(s []*apb.Any) ([]bgp.TunnelEncapSubTLVInterface, error) {
	if len(s) == 0 {
		return nil, nil
	}
	segments := make([]bgp.TunnelEncapSubTLVInterface, len(s))
	for i := 0; i < len(s); i++ {
		value, err := s[i].UnmarshalNew()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal SR Policy Segment: %s", err)
		}
		switch v := value.(type) {
		case *api.SegmentTypeA:
			seg := &bgp.SegmentTypeA{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.EncapSubTLVType(bgp.TypeA),
					Length: 6,
				},
				Label: v.Label,
			}
			if v.Flags.VFlag {
				seg.Flags += 0x80
			}
			if v.Flags.AFlag {
				seg.Flags += 0x40
			}
			if v.Flags.SFlag {
				seg.Flags += 0x20
			}
			if v.Flags.BFlag {
				seg.Flags += 0x10
			}
			segments[i] = seg
		case *api.SegmentTypeB:
			seg := &bgp.SegmentTypeB{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.EncapSubTLVType(bgp.TypeB),
					Length: 18,
				},
				SID: v.GetSid(),
			}
			if v.Flags.VFlag {
				seg.Flags += 0x80
			}
			if v.Flags.AFlag {
				seg.Flags += 0x40
			}
			if v.Flags.SFlag {
				seg.Flags += 0x20
			}
			if v.Flags.BFlag {
				seg.Flags += 0x10
			}
			if v.EndpointBehaviorStructure != nil {
				ebs := v.GetEndpointBehaviorStructure()
				seg.SRv6EBS = &bgp.SRv6EndpointBehaviorStructure{
					Behavior: bgp.SRBehavior(ebs.Behavior),
					BlockLen: uint8(ebs.BlockLen),
					NodeLen:  uint8(ebs.NodeLen),
					FuncLen:  uint8(ebs.FuncLen),
					ArgLen:   uint8(ebs.ArgLen),
				}
			}
			segments[i] = seg
		}
	}
	return segments, nil
}

func UnmarshalPrefixSID(psid *api.PrefixSID) (*bgp.PathAttributePrefixSID, error) {
	t := bgp.BGP_ATTR_TYPE_PREFIX_SID
	s := &bgp.PathAttributePrefixSID{
		PathAttribute: bgp.PathAttribute{
			Flags: bgp.PathAttrFlags[t],
			Type:  t,
		},
		TLVs: make([]bgp.PrefixSIDTLVInterface, 0),
	}
	for _, raw := range psid.Tlvs {
		tlv, err := raw.UnmarshalNew()
		if err != nil {
			return nil, err
		}
		switch v := tlv.(type) {
		case *api.SRv6L3ServiceTLV:
			tlvLength, tlvs, err := UnmarshalSubTLVs(v.SubTlvs)
			if err != nil {
				return nil, err
			}
			o := &bgp.SRv6L3ServiceAttribute{
				TLV: bgp.TLV{
					Type:   bgp.TLVType(5),
					Length: tlvLength,
				},
			}
			s.PathAttribute.Length += tlvLength
			// Storing Sub TLVs in a Service TLV
			o.SubTLVs = append(o.SubTLVs, tlvs...)
			// Adding Service TLV to Path Attribute TLV slice.
			s.TLVs = append(s.TLVs, o)
		default:
			return nil, fmt.Errorf("unknown or not implemented Prefix SID type: %+v", v)
		}
	}
	// Final Path Attribute Length is 3 bytes of the header and 1 byte Reserved1
	s.PathAttribute.Length += (3 + 1)
	return s, nil
}

func UnmarshalSubTLVs(stlvs map[uint32]*api.SRv6TLV) (uint16, []bgp.PrefixSIDTLVInterface, error) {
	p := make([]bgp.PrefixSIDTLVInterface, 0, len(stlvs))
	l := uint16(0)
	// v.SubTlvs is a map by sub tlv type and the value is a slice of sub tlvs of the specific type
	for t, tlv := range stlvs {
		switch t {
		case 1:
			// Sub TLV Type 1 is SRv6 Informational Sub TLV
			for _, stlvRaw := range tlv.Tlv {
				// Instantiating Information Sub TLV
				info := &bgp.SRv6InformationSubTLV{
					SubTLV: bgp.SubTLV{
						Type: bgp.SubTLVType(1),
					},
					SubSubTLVs: make([]bgp.PrefixSIDTLVInterface, 0),
				}
				raw, err := stlvRaw.UnmarshalNew()
				if err != nil {
					return 0, nil, err
				}
				infoProto := raw.(*api.SRv6InformationSubTLV)
				info.SID = make([]byte, len(infoProto.Sid))
				copy(info.SID, infoProto.Sid)
				// TODO Once RFC is published add processing of flags
				info.Flags = 0
				info.EndpointBehavior = uint16(infoProto.EndpointBehavior)
				var sstlvslength uint16
				var sstlvs []bgp.PrefixSIDTLVInterface
				if len(infoProto.SubSubTlvs) != 0 {
					// Processing Sub Sub TLVs
					var err error
					sstlvslength, sstlvs, err = UnmarshalSubSubTLVs(infoProto.SubSubTlvs)
					if err != nil {
						return 0, nil, err
					}
					info.SubSubTLVs = append(info.SubSubTLVs, sstlvs...)
				}
				// SRv6 Information Sub TLV length consists 1 byte Resrved2, 16 bytes SID, 1 byte flags, 2 bytes Endpoint Behavior
				// 1 byte Reserved3 and length of Sub Sub TLVs
				info.SubTLV.Length = 1 + 16 + 1 + 2 + 1 + sstlvslength
				// For total Srv6 Information Sub TLV length, adding 3 bytes of the Sub TLV header
				l += info.SubTLV.Length + 4
				p = append(p, info)
			}
		default:
			return 0, nil, fmt.Errorf("unknown or not implemented Prefix SID Sub TLV type: %d", t)
		}
	}

	return l, p, nil
}

func UnmarshalSubSubTLVs(stlvs map[uint32]*api.SRv6TLV) (uint16, []bgp.PrefixSIDTLVInterface, error) {
	p := make([]bgp.PrefixSIDTLVInterface, 0)
	l := uint16(0)
	// v.SubTlvs is a map by sub tlv type and the value is a slice of sub tlvs of the specific type
	for t, tlv := range stlvs {
		switch t {
		case 1:
			// Sub Sub TLV Type 1 is SRv6 Structure Sub Sub TLV
			for _, stlvRaw := range tlv.Tlv {
				// Instantiating Information Sub TLV
				structure := &bgp.SRv6SIDStructureSubSubTLV{
					SubSubTLV: bgp.SubSubTLV{
						Type:   bgp.SubSubTLVType(1),
						Length: 6,
					},
				}
				raw, err := stlvRaw.UnmarshalNew()
				if err != nil {
					return 0, nil, err
				}
				structureProto := raw.(*api.SRv6StructureSubSubTLV)
				structure.LocalBlockLength = uint8(structureProto.LocalBlockLength)
				structure.LocatorNodeLength = uint8(structureProto.LocalNodeLength)
				structure.FunctionLength = uint8(structureProto.FunctionLength)
				structure.ArgumentLength = uint8(structureProto.ArgumentLength)
				structure.TranspositionLength = uint8(structureProto.TranspositionLength)
				structure.TranspositionOffset = uint8(structureProto.TranspositionOffset)

				// SRv6 Structure Sub Sub TLV length consists of header 3 bytes, 6 bytes of value
				l += 3 + 6
				p = append(p, structure)
			}
		default:
			return 0, nil, fmt.Errorf("unknown or not implemented Prefix SID Sub TLV type: %d", t)
		}
	}

	return l, p, nil
}
