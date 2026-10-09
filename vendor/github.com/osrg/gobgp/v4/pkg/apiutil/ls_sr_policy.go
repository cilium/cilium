// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiutil

import (
	"fmt"
	"math"
	"net/netip"
	"slices"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Conversions between the native RFC 9857 (SR Policy Candidate Path) types in
// pkg/packet/bgp and their protobuf representation.

func lsParseAddr(field, s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s %q: %w", field, s, err)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid %s %q: address zones cannot be encoded in BGP-LS", field, s)
	}
	return a, nil
}

func MarshalLsSrPolicyCandidatePathDescriptor(d *bgp.LsSrPolicyCandidatePathDescriptor) *api.LsSrPolicyCandidatePathDescriptor {
	return &api.LsSrPolicyCandidatePathDescriptor{
		ProtocolOrigin:    uint32(d.ProtocolOrigin),
		Endpoint:          AddrOrEmpty(d.Endpoint),
		Color:             d.Color,
		OriginatorAsn:     d.OriginatorASN,
		OriginatorAddress: AddrOrEmpty(d.OriginatorAddress),
		Discriminator:     d.Discriminator,
	}
}

func UnmarshalLsSrPolicyCandidatePathDescriptor(d *api.LsSrPolicyCandidatePathDescriptor) (*bgp.LsSrPolicyCandidatePathDescriptor, error) {
	if d == nil {
		return nil, fmt.Errorf("SR Policy candidate path descriptor is required")
	}
	endpoint, err := lsParseAddr("endpoint", d.Endpoint)
	if err != nil || !endpoint.IsValid() {
		return nil, fmt.Errorf("invalid endpoint %q", d.Endpoint)
	}
	originator, err := lsParseAddr("originator address", d.OriginatorAddress)
	if err != nil || !originator.IsValid() {
		return nil, fmt.Errorf("invalid originator address %q", d.OriginatorAddress)
	}
	if d.ProtocolOrigin > 0xff {
		return nil, fmt.Errorf("invalid protocol origin %d", d.ProtocolOrigin)
	}
	return &bgp.LsSrPolicyCandidatePathDescriptor{
		ProtocolOrigin:    uint8(d.ProtocolOrigin),
		Endpoint:          endpoint,
		Color:             d.Color,
		OriginatorASN:     d.OriginatorAsn,
		OriginatorAddress: originator,
		Discriminator:     d.Discriminator,
	}, nil
}

func MarshalLsSrPolicyCandidatePathNLRI(n *bgp.LsSrPolicyCandidatePathNLRI) (*api.LsAddrPrefix_LsNLRI, error) {
	lnd, ok := n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor)
	if !ok {
		return nil, fmt.Errorf("invalid local node descriptor type")
	}
	ln, err := MarshalLsNodeDescriptor(lnd.Extract())
	if err != nil {
		return nil, err
	}
	cpd, ok := n.CandidatePathDesc.(*bgp.LsTLVSrPolicyCandidatePathDescriptor)
	if !ok {
		return nil, fmt.Errorf("invalid SR Policy candidate path descriptor type")
	}

	return &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_SrPolicyCandidatePath{
		SrPolicyCandidatePath: &api.LsSrPolicyCandidatePathNLRI{
			LocalNode:               ln,
			CandidatePathDescriptor: MarshalLsSrPolicyCandidatePathDescriptor(cpd.Extract()),
		},
	}}, nil
}

// UnmarshalLsSrPolicyCandidatePathNLRI builds the native NLRI. The NLRI
// length is computed from the descriptors, so callers need not provide it.
// The conversion accepts whatever the wire decoder accepts (RFC 9552
// section 8.2.2), so a route learned from a peer always converts back;
// the RFC 9857 rules for originating a candidate path are enforced by the
// gobgp command instead.
func UnmarshalLsSrPolicyCandidatePathNLRI(n *api.LsSrPolicyCandidatePathNLRI, protocolID bgp.LsProtocolID, identifier uint64) (*bgp.LsAddrPrefix, error) {
	if n == nil {
		return nil, fmt.Errorf("SR Policy candidate path NLRI is required")
	}
	lnd, err := unmarshalLsNodeDescriptor(n.LocalNode, true)
	if err != nil {
		return nil, err
	}
	if lnd.BGPRouterID.IsValid() && (!lnd.BGPRouterID.Is4() || lnd.BGPRouterID.Zone() != "") {
		return nil, fmt.Errorf("headend BGP Router-ID must be an IPv4 address")
	}
	lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

	cpd, err := UnmarshalLsSrPolicyCandidatePathDescriptor(n.CandidatePathDescriptor)
	if err != nil {
		return nil, err
	}
	cpdTLV := bgp.NewLsTLVSrPolicyCandidatePathDescriptor(cpd)

	const lsNLRIHdrLen = 9 // Protocol-ID + Identifier
	length := uint16(lsNLRIHdrLen + lndTLV.Len() + cpdTLV.Len())

	return &bgp.LsAddrPrefix{
		Type:   bgp.LS_NLRI_TYPE_SR_POLICY_CANDIDATE_PATH,
		Length: length,
		NLRI: &bgp.LsSrPolicyCandidatePathNLRI{
			LsNLRI: bgp.LsNLRI{
				NLRIType:   bgp.LS_NLRI_TYPE_SR_POLICY_CANDIDATE_PATH,
				Length:     length,
				ProtocolID: protocolID,
				Identifier: identifier,
			},
			LocalNodeDesc:     &lndTLV,
			CandidatePathDesc: cpdTLV,
		},
	}, nil
}

func marshalLsSrv6EndpointBehavior(eb *bgp.LsSrv6EndpointBehavior) *api.LsSrv6EndpointBehavior {
	if eb == nil {
		return nil
	}
	return &api.LsSrv6EndpointBehavior{
		EndpointBehavior: uint32(eb.EndpointBehavior),
		Flags:            uint32(eb.Flags),
		Algorithm:        uint32(eb.Algorithm),
	}
}

func unmarshalLsSrv6EndpointBehavior(eb *api.LsSrv6EndpointBehavior) *bgp.LsSrv6EndpointBehavior {
	if eb == nil {
		return nil
	}
	return &bgp.LsSrv6EndpointBehavior{
		EndpointBehavior: uint16(eb.EndpointBehavior),
		Flags:            uint8(eb.Flags),
		Algorithm:        uint8(eb.Algorithm),
	}
}

func marshalLsSrv6SIDStructure(ss *bgp.LsSrv6SIDStructure) *api.LsSrv6SIDStructure {
	if ss == nil {
		return nil
	}
	return &api.LsSrv6SIDStructure{
		LocalBlock: uint32(ss.LocalBlock),
		LocalNode:  uint32(ss.LocalNode),
		LocalFunc:  uint32(ss.LocalFunc),
		LocalArg:   uint32(ss.LocalArg),
	}
}

func unmarshalLsSrv6SIDStructure(ss *api.LsSrv6SIDStructure) *bgp.LsSrv6SIDStructure {
	if ss == nil {
		return nil
	}
	return &bgp.LsSrv6SIDStructure{
		LocalBlock: uint8(ss.LocalBlock),
		LocalNode:  uint8(ss.LocalNode),
		LocalFunc:  uint8(ss.LocalFunc),
		LocalArg:   uint8(ss.LocalArg),
	}
}

func MarshalLsSrBindingSID(b *bgp.LsSrBindingSID) *api.LsSrBindingSID {
	if b == nil {
		return nil
	}
	return &api.LsSrBindingSID{
		Flags: &api.LsSrBindingSIDFlags{
			Srv6:        b.Flags.SRv6,
			Allocated:   b.Flags.Allocated,
			Unavailable: b.Flags.Unavailable,
			FromSrlb:    b.Flags.FromSRLB,
			Fallback:    b.Flags.Fallback,
		},
		Label:          b.Label,
		SpecifiedLabel: b.SpecifiedLabel,
		Sid:            AddrOrEmpty(b.SID),
		SpecifiedSid:   AddrOrEmpty(b.SpecifiedSID),
	}
}

func UnmarshalLsSrBindingSID(b *api.LsSrBindingSID) (*bgp.LsSrBindingSID, error) {
	if b == nil {
		return nil, nil
	}
	if b.Label > 0xfffff || b.SpecifiedLabel > 0xfffff {
		return nil, fmt.Errorf("binding SID label exceeds 20 bits")
	}
	sid, err := lsParseAddr("binding SID", b.Sid)
	if err != nil {
		return nil, err
	}
	specified, err := lsParseAddr("specified binding SID", b.SpecifiedSid)
	if err != nil {
		return nil, err
	}
	n := &bgp.LsSrBindingSID{
		Label:          b.Label,
		SpecifiedLabel: b.SpecifiedLabel,
		SID:            sid,
		SpecifiedSID:   specified,
	}
	if b.Flags != nil {
		n.Flags = bgp.LsSrBindingSIDFlags{
			SRv6:        b.Flags.Srv6,
			Allocated:   b.Flags.Allocated,
			Unavailable: b.Flags.Unavailable,
			FromSRLB:    b.Flags.FromSrlb,
			Fallback:    b.Flags.Fallback,
		}
	}
	if n.Flags.SRv6 {
		if b.Label != 0 || b.SpecifiedLabel != 0 {
			return nil, fmt.Errorf("SRv6 binding SID cannot carry MPLS labels")
		}
		if err := validateLsSrv6Addrs(sid, specified); err != nil {
			return nil, err
		}
	} else if sid.IsValid() || specified.IsValid() {
		return nil, fmt.Errorf("MPLS binding SID cannot carry IPv6 SIDs")
	}
	return n, nil
}

func validateLsSrv6Addrs(addrs ...netip.Addr) error {
	for _, addr := range addrs {
		if addr.IsValid() && (!addr.Is6() || addr.Zone() != "") {
			return fmt.Errorf("SRv6 SID must be an IPv6 address")
		}
	}
	return nil
}

func validateLsSrv6SubTLVs(eb *api.LsSrv6EndpointBehavior, ss *api.LsSrv6SIDStructure) error {
	if eb != nil && (eb.EndpointBehavior > 0xffff || eb.Flags > 0xff || eb.Algorithm > 0xff) {
		return fmt.Errorf("SRv6 endpoint behavior field out of range")
	}
	if ss != nil && (ss.LocalBlock > 128 || ss.LocalNode > 128 || ss.LocalFunc > 128 || ss.LocalArg > 128 ||
		ss.LocalBlock+ss.LocalNode+ss.LocalFunc+ss.LocalArg > 128) {
		return fmt.Errorf("SRv6 SID structure exceeds 128 bits")
	}
	return nil
}

func MarshalLsSrv6BindingSID(b *bgp.LsSrv6BindingSID) *api.LsSrv6BindingSID {
	if b == nil {
		return nil
	}
	return &api.LsSrv6BindingSID{
		Flags: &api.LsSrv6BindingSIDFlags{
			Allocated:   b.Flags.Allocated,
			Unavailable: b.Flags.Unavailable,
			Fallback:    b.Flags.Fallback,
		},
		Sid:              AddrOrEmpty(b.SID),
		SpecifiedSid:     AddrOrEmpty(b.SpecifiedSID),
		EndpointBehavior: marshalLsSrv6EndpointBehavior(b.EndpointBehavior),
		SidStructure:     marshalLsSrv6SIDStructure(b.SIDStructure),
	}
}

func UnmarshalLsSrv6BindingSID(b *api.LsSrv6BindingSID) (*bgp.LsSrv6BindingSID, error) {
	if b == nil {
		return nil, nil
	}
	if err := validateLsSrv6SubTLVs(b.EndpointBehavior, b.SidStructure); err != nil {
		return nil, err
	}
	sid, err := lsParseAddr("SRv6 binding SID", b.Sid)
	if err != nil {
		return nil, err
	}
	specified, err := lsParseAddr("specified SRv6 binding SID", b.SpecifiedSid)
	if err != nil {
		return nil, err
	}
	if err := validateLsSrv6Addrs(sid, specified); err != nil {
		return nil, err
	}
	n := &bgp.LsSrv6BindingSID{
		SID:              sid,
		SpecifiedSID:     specified,
		EndpointBehavior: unmarshalLsSrv6EndpointBehavior(b.EndpointBehavior),
		SIDStructure:     unmarshalLsSrv6SIDStructure(b.SidStructure),
	}
	if b.Flags != nil {
		n.Flags = bgp.LsSrv6BindingSIDFlags{
			Allocated:   b.Flags.Allocated,
			Unavailable: b.Flags.Unavailable,
			Fallback:    b.Flags.Fallback,
		}
	}
	return n, nil
}

func MarshalLsSrCandidatePathState(s *bgp.LsSrCandidatePathState) *api.LsSrCandidatePathState {
	if s == nil {
		return nil
	}
	return &api.LsSrCandidatePathState{
		Priority: uint32(s.Priority),
		Flags: &api.LsSrCandidatePathStateFlags{
			Shutdown:        s.Flags.Shutdown,
			Active:          s.Flags.Active,
			Backup:          s.Flags.Backup,
			Evaluated:       s.Flags.Evaluated,
			ValidSidList:    s.Flags.ValidSIDList,
			OnDemand:        s.Flags.OnDemand,
			Delegated:       s.Flags.Delegated,
			Provisioned:     s.Flags.Provisioned,
			DropUponInvalid: s.Flags.DropUponInvalid,
			TransitEligible: s.Flags.TransitEligible,
			Dropping:        s.Flags.Dropping,
		},
		Preference: s.Preference,
	}
}

func UnmarshalLsSrCandidatePathState(s *api.LsSrCandidatePathState) (*bgp.LsSrCandidatePathState, error) {
	if s == nil {
		return nil, nil
	}
	if s.Priority > 0xff {
		return nil, fmt.Errorf("invalid candidate path priority %d", s.Priority)
	}
	n := &bgp.LsSrCandidatePathState{
		Priority:   uint8(s.Priority),
		Preference: s.Preference,
	}
	if s.Flags != nil {
		n.Flags = bgp.LsSrCandidatePathStateFlags{
			Shutdown:        s.Flags.Shutdown,
			Active:          s.Flags.Active,
			Backup:          s.Flags.Backup,
			Evaluated:       s.Flags.Evaluated,
			ValidSIDList:    s.Flags.ValidSidList,
			OnDemand:        s.Flags.OnDemand,
			Delegated:       s.Flags.Delegated,
			Provisioned:     s.Flags.Provisioned,
			DropUponInvalid: s.Flags.DropUponInvalid,
			TransitEligible: s.Flags.TransitEligible,
			Dropping:        s.Flags.Dropping,
		}
	}
	return n, nil
}

func MarshalLsSrSegment(s *bgp.LsSrSegment) *api.LsSrSegment {
	return &api.LsSrSegment{
		SegmentType: api.LsSrSegmentType(s.SegmentType),
		Flags: &api.LsSrSegmentFlags{
			SidPresent:     s.Flags.SIDPresent,
			Explicit:       s.Flags.Explicit,
			Verified:       s.Flags.Verified,
			Resolved:       s.Flags.Resolved,
			AlgorithmValid: s.Flags.AlgorithmValid,
		},
		Label:             s.Label,
		Sid:               AddrOrEmpty(s.SID),
		Algorithm:         uint32(s.Algorithm),
		LocalAddress:      AddrOrEmpty(s.LocalAddress),
		RemoteAddress:     AddrOrEmpty(s.RemoteAddress),
		LocalInterfaceId:  s.LocalInterfaceID,
		RemoteInterfaceId: s.RemoteInterfaceID,
		EndpointBehavior:  marshalLsSrv6EndpointBehavior(s.EndpointBehavior),
		SidStructure:      marshalLsSrv6SIDStructure(s.SIDStructure),
	}
}

// validateLsSrSegment checks fields whose interpretation depends on the segment type,
// so that an inconsistent segment taken in through the API is refused with
// a specific error up front instead of a generic one at serialization.
// Every value the wire decoder can produce passes, so a segment learned
// from a peer always converts back through the API.
func validateLsSrSegment(s *bgp.LsSrSegment) error {
	if s.SegmentType < bgp.LS_SR_SEGMENT_TYPE_A_MPLS_LABEL || s.SegmentType > bgp.LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6 {
		return fmt.Errorf("unknown SR segment type %d", s.SegmentType)
	}
	if s.Label > 0xfffff {
		return fmt.Errorf("SR segment label exceeds 20 bits: %d", s.Label)
	}
	if s.SID.IsValid() && (!s.SegmentType.IsSRv6() || !s.SID.Is6() || s.SID.Zone() != "") {
		return fmt.Errorf("segment SID must be an IPv6 address on an SRv6 segment")
	}
	if s.SegmentType.IsSRv6() && (s.Label != 0 || s.Flags.SIDPresent && !s.SID.IsValid()) {
		return fmt.Errorf("SRv6 segment requires a SID instead of a label")
	}
	check := func(addr netip.Addr, ipv6 bool, field string) error {
		if !addr.IsValid() || addr.Zone() != "" || addr.Is6() != ipv6 {
			return fmt.Errorf("invalid %s for SR segment type %s", field, s.SegmentType)
		}
		return nil
	}
	switch s.SegmentType {
	case bgp.LS_SR_SEGMENT_TYPE_C_IPV4_NODE, bgp.LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE, bgp.LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		if err := check(s.LocalAddress, false, "local address"); err != nil {
			return err
		}
	case bgp.LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS, bgp.LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS,
		bgp.LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS, bgp.LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6,
		bgp.LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6, bgp.LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		if err := check(s.LocalAddress, true, "local address"); err != nil {
			return err
		}
	}
	switch s.SegmentType {
	case bgp.LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:
		return check(s.RemoteAddress, false, "remote address")
	case bgp.LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, bgp.LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS,
		bgp.LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6, bgp.LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:
		return check(s.RemoteAddress, true, "remote address")
	}
	return nil
}

func UnmarshalLsSrSegment(s *api.LsSrSegment) (*bgp.LsSrSegment, error) {
	if s == nil {
		return nil, fmt.Errorf("SR segment is required")
	}
	if s.SegmentType < api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_A_MPLS_LABEL || s.SegmentType > api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6 {
		return nil, fmt.Errorf("invalid SR segment type %d", s.SegmentType)
	}
	if s.Algorithm > 0xff {
		return nil, fmt.Errorf("invalid SR segment algorithm %d", s.Algorithm)
	}
	if err := validateLsSrv6SubTLVs(s.EndpointBehavior, s.SidStructure); err != nil {
		return nil, err
	}
	sid, err := lsParseAddr("segment SID", s.Sid)
	if err != nil {
		return nil, err
	}
	local, err := lsParseAddr("segment local address", s.LocalAddress)
	if err != nil {
		return nil, err
	}
	remote, err := lsParseAddr("segment remote address", s.RemoteAddress)
	if err != nil {
		return nil, err
	}
	n := &bgp.LsSrSegment{
		SegmentType:       bgp.LsSrSegmentType(s.SegmentType),
		Label:             s.Label,
		SID:               sid,
		Algorithm:         uint8(s.Algorithm),
		LocalAddress:      local,
		RemoteAddress:     remote,
		LocalInterfaceID:  s.LocalInterfaceId,
		RemoteInterfaceID: s.RemoteInterfaceId,
		EndpointBehavior:  unmarshalLsSrv6EndpointBehavior(s.EndpointBehavior),
		SIDStructure:      unmarshalLsSrv6SIDStructure(s.SidStructure),
	}
	if s.Flags != nil {
		n.Flags = bgp.LsSrSegmentFlags{
			SIDPresent:     s.Flags.SidPresent,
			Explicit:       s.Flags.Explicit,
			Verified:       s.Flags.Verified,
			Resolved:       s.Flags.Resolved,
			AlgorithmValid: s.Flags.AlgorithmValid,
		}
	}
	if err := validateLsSrSegment(n); err != nil {
		return nil, err
	}
	return n, nil
}

func MarshalLsSrSegmentListMetric(m *bgp.LsSrSegmentListMetric) *api.LsSrSegmentListMetric {
	return &api.LsSrSegmentListMetric{
		MetricType: uint32(m.MetricType),
		Flags: &api.LsSrSegmentListMetricFlags{
			Margin:   m.Flags.Margin,
			Absolute: m.Flags.Absolute,
			Bound:    m.Flags.Bound,
			Value:    m.Flags.Value,
		},
		Margin: m.Margin,
		Bound:  m.Bound,
		Value:  m.Value,
	}
}

func UnmarshalLsSrSegmentListMetric(m *api.LsSrSegmentListMetric) (*bgp.LsSrSegmentListMetric, error) {
	if m == nil {
		return nil, fmt.Errorf("SR segment list metric is required")
	}
	if m.MetricType > 0xff {
		return nil, fmt.Errorf("invalid SR segment list metric type %d", m.MetricType)
	}
	n := &bgp.LsSrSegmentListMetric{
		MetricType: uint8(m.MetricType),
		Margin:     m.Margin,
		Bound:      m.Bound,
		Value:      m.Value,
	}
	if m.Flags != nil {
		n.Flags = bgp.LsSrSegmentListMetricFlags{
			Margin:   m.Flags.Margin,
			Absolute: m.Flags.Absolute,
			Bound:    m.Flags.Bound,
			Value:    m.Flags.Value,
		}
	}
	return n, nil
}

func MarshalLsSrSegmentList(sl *bgp.LsSrSegmentList) *api.LsSrSegmentList {
	out := &api.LsSrSegmentList{
		Flags: &api.LsSrSegmentListFlags{
			Srv6:           sl.Flags.SRv6,
			Explicit:       sl.Flags.Explicit,
			Computed:       sl.Flags.Computed,
			Verified:       sl.Flags.Verified,
			Resolved:       sl.Flags.Resolved,
			Failed:         sl.Flags.Failed,
			AllAlgorithm:   sl.Flags.AllAlgorithm,
			AllTopology:    sl.Flags.AllTopology,
			RemovedByFault: sl.Flags.RemovedByFault,
		},
		Mtid:      uint32(sl.MTID),
		Algorithm: uint32(sl.Algorithm),
		Weight:    sl.Weight,
		Segments:  make([]*api.LsSrSegment, 0, len(sl.Segments)),
		Metrics:   make([]*api.LsSrSegmentListMetric, 0, len(sl.Metrics)),
	}
	for i := range sl.Segments {
		out.Segments = append(out.Segments, MarshalLsSrSegment(&sl.Segments[i]))
	}
	for i := range sl.Metrics {
		out.Metrics = append(out.Metrics, MarshalLsSrSegmentListMetric(&sl.Metrics[i]))
	}
	if sl.Bandwidth != nil {
		out.Bandwidth = &api.LsSrSegmentListBandwidth{Bandwidth: *sl.Bandwidth}
	}
	if sl.Identifier != nil {
		out.Identifier = &api.LsSrSegmentListIdentifier{Identifier: *sl.Identifier}
	}
	return out
}

func UnmarshalLsSrSegmentList(sl *api.LsSrSegmentList) (*bgp.LsSrSegmentList, error) {
	if sl == nil {
		return nil, fmt.Errorf("SR segment list is required")
	}
	if sl.Mtid > 0xffff {
		return nil, fmt.Errorf("invalid SR segment list MTID %d", sl.Mtid)
	}
	if sl.Algorithm > 0xff {
		return nil, fmt.Errorf("invalid SR segment list algorithm %d", sl.Algorithm)
	}
	n := &bgp.LsSrSegmentList{
		MTID:      uint16(sl.Mtid),
		Algorithm: uint8(sl.Algorithm),
		Weight:    sl.Weight,
		Segments:  make([]bgp.LsSrSegment, 0, len(sl.Segments)),
	}
	if sl.Flags != nil {
		n.Flags = bgp.LsSrSegmentListFlags{
			SRv6:           sl.Flags.Srv6,
			Explicit:       sl.Flags.Explicit,
			Computed:       sl.Flags.Computed,
			Verified:       sl.Flags.Verified,
			Resolved:       sl.Flags.Resolved,
			Failed:         sl.Flags.Failed,
			AllAlgorithm:   sl.Flags.AllAlgorithm,
			AllTopology:    sl.Flags.AllTopology,
			RemovedByFault: sl.Flags.RemovedByFault,
		}
	}
	for _, s := range sl.Segments {
		seg, err := UnmarshalLsSrSegment(s)
		if err != nil {
			return nil, err
		}
		n.Segments = append(n.Segments, *seg)
	}
	for _, m := range sl.Metrics {
		metric, err := UnmarshalLsSrSegmentListMetric(m)
		if err != nil {
			return nil, err
		}
		n.Metrics = append(n.Metrics, *metric)
	}
	if sl.Bandwidth != nil {
		bw := sl.Bandwidth.Bandwidth
		if bw < 0 || math.IsNaN(float64(bw)) || math.IsInf(float64(bw), 0) {
			return nil, fmt.Errorf("invalid SR segment list bandwidth")
		}
		n.Bandwidth = &bw
	}
	if sl.Identifier != nil {
		id := sl.Identifier.Identifier
		n.Identifier = &id
	}
	// The TLV length is 2 octets; a long enough segment list can exceed
	// it, which Serialize reports as a length mismatch.
	if _, err := bgp.NewLsTLVSrSegmentList(n).Serialize(); err != nil {
		return nil, err
	}
	return n, nil
}

func MarshalLsSrCandidatePathConstraints(c *bgp.LsSrCandidatePathConstraints) *api.LsSrCandidatePathConstraints {
	if c == nil {
		return nil
	}
	out := &api.LsSrCandidatePathConstraints{
		Flags: &api.LsSrCandidatePathConstraintsFlags{
			Srv6:            c.Flags.SRv6,
			ProtectedOnly:   c.Flags.ProtectedOnly,
			UnprotectedOnly: c.Flags.UnprotectedOnly,
			AlgorithmOnly:   c.Flags.AlgorithmOnly,
			TopologyOnly:    c.Flags.TopologyOnly,
			Strict:          c.Flags.Strict,
			Fixed:           c.Flags.Fixed,
			HopByHop:        c.Flags.HopByHop,
		},
		Mtid:      uint32(c.MTID),
		Algorithm: uint32(c.Algorithm),
		Srlgs:     slices.Clone(c.SRLGs),
	}
	if c.Affinity != nil {
		out.Affinity = &api.LsSrAffinityConstraint{
			ExcludeAny: slices.Clone(c.Affinity.ExcludeAny),
			IncludeAny: slices.Clone(c.Affinity.IncludeAny),
			IncludeAll: slices.Clone(c.Affinity.IncludeAll),
		}
	}
	if c.Bandwidth != nil {
		out.Bandwidth = &api.LsSrBandwidthConstraint{Bandwidth: *c.Bandwidth}
	}
	if d := c.DisjointGroup; d != nil {
		out.DisjointGroup = &api.LsSrDisjointGroupConstraint{
			RequestFlags: &api.LsSrDisjointGroupRequestFlags{
				Srlg:             d.RequestFlags.SRLG,
				Node:             d.RequestFlags.Node,
				Link:             d.RequestFlags.Link,
				Fallback:         d.RequestFlags.Fallback,
				BestPathFallback: d.RequestFlags.BestPathFallback,
			},
			StatusFlags: &api.LsSrDisjointGroupStatusFlags{
				Srlg:             d.StatusFlags.SRLG,
				Node:             d.StatusFlags.Node,
				Link:             d.StatusFlags.Link,
				Fallback:         d.StatusFlags.Fallback,
				BestPathFallback: d.StatusFlags.BestPathFallback,
				Invalidated:      d.StatusFlags.Invalidated,
			},
			GroupId:         d.GroupID,
			PcepAssociation: slices.Clone(d.PcepAssociation),
		}
	}
	if b := c.BidirectionalGroup; b != nil {
		out.BidirectionalGroup = &api.LsSrBidirectionalGroupConstraint{
			Flags: &api.LsSrBidirectionalGroupFlags{
				Reverse:  b.Flags.Reverse,
				CoRouted: b.Flags.CoRouted,
			},
			GroupId:         b.GroupID,
			PcepAssociation: slices.Clone(b.PcepAssociation),
		}
	}
	for i := range c.Metrics {
		m := &c.Metrics[i]
		out.Metrics = append(out.Metrics, &api.LsSrMetricConstraint{
			MetricType: uint32(m.MetricType),
			Flags: &api.LsSrMetricConstraintFlags{
				Optimization: m.Flags.Optimization,
				Margin:       m.Flags.Margin,
				Absolute:     m.Flags.Absolute,
				Bound:        m.Flags.Bound,
			},
			Margin: m.Margin,
			Bound:  m.Bound,
		})
	}
	return out
}

// validateLsSrPcepAssociation checks the identifier of a group constraint
// that carries a PCEP ASSOCIATION Object instead of a 4-octet group ID.
// The object is a 4-octet header followed by a mandatory body, so a
// 4-octet identifier on the wire is always a plain group ID; accepting a
// 4-octet object here would silently turn it into one on the way back.
func validateLsSrPcepAssociation(groupID uint32, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if len(b) <= 4 {
		return fmt.Errorf("PCEP association object must be longer than 4 octets")
	}
	if groupID != 0 {
		return fmt.Errorf("specify a group ID or a PCEP association object, not both")
	}
	return nil
}

func UnmarshalLsSrCandidatePathConstraints(c *api.LsSrCandidatePathConstraints) (*bgp.LsSrCandidatePathConstraints, error) {
	if c == nil {
		return nil, nil
	}
	if c.Mtid > 0xffff {
		return nil, fmt.Errorf("invalid SR candidate path constraints MTID %d", c.Mtid)
	}
	if c.Algorithm > 0xff {
		return nil, fmt.Errorf("invalid SR candidate path constraints algorithm %d", c.Algorithm)
	}
	n := &bgp.LsSrCandidatePathConstraints{
		MTID:      uint16(c.Mtid),
		Algorithm: uint8(c.Algorithm),
		SRLGs:     slices.Clone(c.Srlgs),
	}
	if c.Flags != nil {
		n.Flags = bgp.LsSrCandidatePathConstraintsFlags{
			SRv6:            c.Flags.Srv6,
			ProtectedOnly:   c.Flags.ProtectedOnly,
			UnprotectedOnly: c.Flags.UnprotectedOnly,
			AlgorithmOnly:   c.Flags.AlgorithmOnly,
			TopologyOnly:    c.Flags.TopologyOnly,
			Strict:          c.Flags.Strict,
			Fixed:           c.Flags.Fixed,
			HopByHop:        c.Flags.HopByHop,
		}
	}
	if a := c.Affinity; a != nil {
		if len(a.ExcludeAny) > 0xff || len(a.IncludeAny) > 0xff || len(a.IncludeAll) > 0xff {
			return nil, fmt.Errorf("SR affinity constraint EAG exceeds 255 words")
		}
		n.Affinity = &bgp.LsSrAffinityConstraint{
			ExcludeAny: slices.Clone(a.ExcludeAny),
			IncludeAny: slices.Clone(a.IncludeAny),
			IncludeAll: slices.Clone(a.IncludeAll),
		}
	}
	if c.Bandwidth != nil {
		bw := c.Bandwidth.Bandwidth
		if bw < 0 || math.IsNaN(float64(bw)) || math.IsInf(float64(bw), 0) {
			return nil, fmt.Errorf("invalid SR bandwidth constraint")
		}
		n.Bandwidth = &bw
	}
	if d := c.DisjointGroup; d != nil {
		if err := validateLsSrPcepAssociation(d.GroupId, d.PcepAssociation); err != nil {
			return nil, err
		}
		n.DisjointGroup = &bgp.LsSrDisjointGroupConstraint{GroupID: d.GroupId, PcepAssociation: slices.Clone(d.PcepAssociation)}
		if d.RequestFlags != nil {
			n.DisjointGroup.RequestFlags = bgp.LsSrDisjointGroupRequestFlags{
				SRLG:             d.RequestFlags.Srlg,
				Node:             d.RequestFlags.Node,
				Link:             d.RequestFlags.Link,
				Fallback:         d.RequestFlags.Fallback,
				BestPathFallback: d.RequestFlags.BestPathFallback,
			}
		}
		if d.StatusFlags != nil {
			n.DisjointGroup.StatusFlags = bgp.LsSrDisjointGroupStatusFlags{
				SRLG:             d.StatusFlags.Srlg,
				Node:             d.StatusFlags.Node,
				Link:             d.StatusFlags.Link,
				Fallback:         d.StatusFlags.Fallback,
				BestPathFallback: d.StatusFlags.BestPathFallback,
				Invalidated:      d.StatusFlags.Invalidated,
			}
		}
	}
	if b := c.BidirectionalGroup; b != nil {
		if err := validateLsSrPcepAssociation(b.GroupId, b.PcepAssociation); err != nil {
			return nil, err
		}
		n.BidirectionalGroup = &bgp.LsSrBidirectionalGroupConstraint{GroupID: b.GroupId, PcepAssociation: slices.Clone(b.PcepAssociation)}
		if b.Flags != nil {
			n.BidirectionalGroup.Flags = bgp.LsSrBidirectionalGroupFlags{Reverse: b.Flags.Reverse, CoRouted: b.Flags.CoRouted}
		}
	}
	for _, m := range c.Metrics {
		if m == nil {
			return nil, fmt.Errorf("SR metric constraint is required")
		}
		if m.MetricType > 0xff {
			return nil, fmt.Errorf("invalid SR metric constraint type %d", m.MetricType)
		}
		metric := bgp.LsSrMetricConstraint{MetricType: uint8(m.MetricType), Margin: m.Margin, Bound: m.Bound}
		if m.Flags != nil {
			metric.Flags = bgp.LsSrMetricConstraintFlags{
				Optimization: m.Flags.Optimization,
				Margin:       m.Flags.Margin,
				Absolute:     m.Flags.Absolute,
				Bound:        m.Flags.Bound,
			}
		}
		n.Metrics = append(n.Metrics, metric)
	}
	// The TLV length is 2 octets; large association objects can exceed
	// it, which Serialize reports as a length mismatch.
	if _, err := bgp.NewLsTLVSrCandidatePathConstraints(n).Serialize(); err != nil {
		return nil, err
	}
	return n, nil
}

func MarshalLsAttributeSrPolicy(sp *bgp.LsAttributeSrPolicy) *api.LsAttributeSrPolicy {
	out := &api.LsAttributeSrPolicy{
		BindingSid:  MarshalLsSrBindingSID(sp.BindingSID),
		State:       MarshalLsSrCandidatePathState(sp.State),
		Constraints: MarshalLsSrCandidatePathConstraints(sp.Constraints),
	}
	for i := range sp.Srv6BindingSIDs {
		out.Srv6BindingSids = append(out.Srv6BindingSids, MarshalLsSrv6BindingSID(&sp.Srv6BindingSIDs[i]))
	}
	// The names are optional on both sides: a zero-length name TLV is
	// valid (RFC 9857 sections 5.4 and 5.5) and distinct from an absent one.
	if sp.CandidatePathName != nil {
		name := *sp.CandidatePathName
		out.CandidatePathName = &name
	}
	if sp.PolicyName != nil {
		name := *sp.PolicyName
		out.PolicyName = &name
	}
	for i := range sp.SegmentLists {
		out.SegmentLists = append(out.SegmentLists, MarshalLsSrSegmentList(&sp.SegmentLists[i]))
	}
	return out
}

func UnmarshalLsAttributeSrPolicy(sp *api.LsAttributeSrPolicy) (*bgp.LsAttributeSrPolicy, error) {
	n := &bgp.LsAttributeSrPolicy{}
	if sp == nil {
		return n, nil
	}

	var err error
	if n.BindingSID, err = UnmarshalLsSrBindingSID(sp.BindingSid); err != nil {
		return nil, err
	}
	for _, bsid := range sp.Srv6BindingSids {
		if bsid == nil {
			return nil, fmt.Errorf("SRv6 binding SID is required")
		}
		sid, err := UnmarshalLsSrv6BindingSID(bsid)
		if err != nil {
			return nil, err
		}
		n.Srv6BindingSIDs = append(n.Srv6BindingSIDs, *sid)
	}
	if n.State, err = UnmarshalLsSrCandidatePathState(sp.State); err != nil {
		return nil, err
	}
	if sp.CandidatePathName != nil {
		if len(*sp.CandidatePathName) > 0xffff {
			return nil, fmt.Errorf("candidate path name exceeds the TLV size")
		}
		name := *sp.CandidatePathName
		n.CandidatePathName = &name
	}
	if sp.PolicyName != nil {
		if len(*sp.PolicyName) > 0xffff {
			return nil, fmt.Errorf("policy name exceeds the TLV size")
		}
		name := *sp.PolicyName
		n.PolicyName = &name
	}
	if n.Constraints, err = UnmarshalLsSrCandidatePathConstraints(sp.Constraints); err != nil {
		return nil, err
	}
	for _, sl := range sp.SegmentLists {
		list, err := UnmarshalLsSrSegmentList(sl)
		if err != nil {
			return nil, err
		}
		n.SegmentLists = append(n.SegmentLists, *list)
	}
	return n, nil
}
