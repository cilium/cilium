// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"errors"
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/time"
)

// ToGoBGPPath converts the Agent Path type to the GoBGP Path type
func ToGoBGPPath(p *types.Path) (*gobgp.Path, error) {
	nlri, err := apiutil.MarshalNLRI(p.NLRI)
	if err != nil {
		return nil, fmt.Errorf("failed to convert NLRI: %w", err)
	}

	pattrs, err := apiutil.MarshalPathAttributes(p.PathAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PathAttribute: %w", err)
	}

	// ageTimestamp is Path's creation time stamp.
	// It is calculated by subtraction of the AgeNanoseconds from the current timestamp.
	ageTimestamp := timestamppb.New(time.Now().Add(time.Duration(-1 * p.AgeNanoseconds)))

	family := toGoBGPFamily(p.Family)

	// infer family from NLRI if not provided
	if family.Afi == gobgp.Family_AFI_UNKNOWN {
		family = &gobgp.Family{
			Afi:  gobgp.Family_Afi(p.NLRI.AFI()),
			Safi: gobgp.Family_Safi(p.NLRI.SAFI()),
		}
	}

	return &gobgp.Path{
		Nlri:   nlri,
		Pattrs: pattrs,
		Age:    ageTimestamp,
		Best:   p.Best,
		Family: family,
		Uuid:   p.UUID,
	}, nil
}

// ToAgentPath converts the GoBGP Path type to the Agent Path type
func ToAgentPath(p *gobgp.Path) (*types.Path, error) {
	family := bgp.AfiSafiToRouteFamily(uint16(p.Family.Afi), uint8(p.Family.Safi))

	nlri, err := apiutil.UnmarshalNLRI(family, p.Nlri)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Nlri: %w", err)
	}

	pattrs, err := apiutil.UnmarshalPathAttributes(p.Pattrs)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Pattrs: %w", err)
	}

	// ageNano is time since the Path was created in nanoseconds.
	// It is calculated by difference in time from age timestamp till now.
	ageNano := int64(time.Since(p.Age.AsTime()))

	return &types.Path{
		NLRI:           nlri,
		Family:         toAgentFamily(p.Family),
		PathAttributes: pattrs,
		AgeNanoseconds: ageNano,
		Best:           p.Best,
		UUID:           p.Uuid,
	}, nil
}

// ToAgentPaths converts slice of the GoBGP Path type to slice of the Agent Path type
func ToAgentPaths(paths []*gobgp.Path) ([]*types.Path, error) {
	errs := []error{}
	ps := []*types.Path{}

	for _, path := range paths {
		p, err := ToAgentPath(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ps = append(ps, p)
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return ps, nil
}

func toGoBGPFamily(family types.Family) *gobgp.Family {
	return &gobgp.Family{
		Afi:  toGoBGPAfi(family.Afi),
		Safi: toGoBGPSafi(family.Safi),
	}
}

func toGoBGPAfi(a types.Afi) gobgp.Family_Afi {
	switch a {
	case types.AfiUnknown:
		return gobgp.Family_AFI_UNKNOWN
	case types.AfiIPv4:
		return gobgp.Family_AFI_IP
	case types.AfiIPv6:
		return gobgp.Family_AFI_IP6
	case types.AfiL2VPN:
		return gobgp.Family_AFI_L2VPN
	case types.AfiLS:
		return gobgp.Family_AFI_LS
	case types.AfiOpaque:
		return gobgp.Family_AFI_OPAQUE
	default:
		return gobgp.Family_AFI_UNKNOWN
	}
}

func toGoBGPSafi(s types.Safi) gobgp.Family_Safi {
	switch s {
	case types.SafiUnknown:
		return gobgp.Family_SAFI_UNKNOWN
	case types.SafiUnicast:
		return gobgp.Family_SAFI_UNICAST
	case types.SafiMulticast:
		return gobgp.Family_SAFI_MULTICAST
	case types.SafiMplsLabel:
		return gobgp.Family_SAFI_MPLS_LABEL
	case types.SafiEncapsulation:
		return gobgp.Family_SAFI_ENCAPSULATION
	case types.SafiVpls:
		return gobgp.Family_SAFI_VPLS
	case types.SafiEvpn:
		return gobgp.Family_SAFI_EVPN
	case types.SafiLs:
		return gobgp.Family_SAFI_LS
	case types.SafiSrPolicy:
		return gobgp.Family_SAFI_SR_POLICY
	case types.SafiMup:
		return gobgp.Family_SAFI_MUP
	case types.SafiMplsVpn:
		return gobgp.Family_SAFI_MPLS_VPN
	case types.SafiMplsVpnMulticast:
		return gobgp.Family_SAFI_MPLS_VPN_MULTICAST
	case types.SafiRouteTargetConstraints:
		return gobgp.Family_SAFI_ROUTE_TARGET_CONSTRAINTS
	case types.SafiFlowSpecUnicast:
		return gobgp.Family_SAFI_FLOW_SPEC_UNICAST
	case types.SafiFlowSpecVpn:
		return gobgp.Family_SAFI_FLOW_SPEC_VPN
	case types.SafiKeyValue:
		return gobgp.Family_SAFI_KEY_VALUE
	default:
		return gobgp.Family_SAFI_UNKNOWN
	}
}

func toGoBGPPolicy(apiPolicy *types.RoutePolicy) (*gobgp.Policy, []*gobgp.DefinedSet) {
	var definedSets []*gobgp.DefinedSet

	policy := &gobgp.Policy{
		Name: apiPolicy.Name,
	}
	for i, stmt := range apiPolicy.Statements {
		statement, dSets := toGoBGPPolicyStatement(stmt, policyStatementName(apiPolicy.Name, i))
		policy.Statements = append(policy.Statements, statement)
		definedSets = append(definedSets, dSets...)
	}

	return policy, definedSets
}

func toAgentPolicy(p *gobgp.Policy, definedSets map[string]*gobgp.DefinedSet, assignment *gobgp.PolicyAssignment) *types.RoutePolicy {
	policy := &types.RoutePolicy{
		Name: p.Name,
		Type: toAgentPolicyType(assignment.Direction),
	}
	for _, s := range p.Statements {
		policy.Statements = append(policy.Statements, toAgentPolicyStatement(s, definedSets))
	}
	return policy
}

func toGoBGPPolicyStatement(apiStatement *types.RoutePolicyStatement, name string) (*gobgp.Statement, []*gobgp.DefinedSet) {
	var definedSets []*gobgp.DefinedSet

	s := &gobgp.Statement{
		Name:       name,
		Conditions: &gobgp.Conditions{},
		Actions: &gobgp.Actions{
			RouteAction: toGoBGPRouteAction(apiStatement.Actions.RouteAction),
		},
	}

	// defined set to match neighbor
	if len(apiStatement.Conditions.MatchNeighbors) > 0 {
		ds := &gobgp.DefinedSet{
			DefinedType: gobgp.DefinedType_NEIGHBOR,
			Name:        policyNeighborDefinedSetName(name),
			List:        apiStatement.Conditions.MatchNeighbors,
		}
		s.Conditions.NeighborSet = &gobgp.MatchSet{
			Type: gobgp.MatchSet_ANY, // any of the configured neighbors
			Name: ds.Name,
		}
		definedSets = append(definedSets, ds)
	}

	// defined set to match prefixes
	if len(apiStatement.Conditions.MatchPrefixes) > 0 {
		ds := &gobgp.DefinedSet{
			DefinedType: gobgp.DefinedType_PREFIX,
			Name:        policyPrefixDefinedSetName(name),
		}
		for _, prefix := range apiStatement.Conditions.MatchPrefixes {
			p := &gobgp.Prefix{
				IpPrefix:      prefix.CIDR.String(),
				MaskLengthMin: uint32(prefix.PrefixLenMin),
				MaskLengthMax: uint32(prefix.PrefixLenMax),
			}
			ds.Prefixes = append(ds.Prefixes, p)
		}
		s.Conditions.PrefixSet = &gobgp.MatchSet{
			Type: gobgp.MatchSet_ANY, // any of the configured prefixes
			Name: ds.Name,
		}
		definedSets = append(definedSets, ds)
	}

	// match address families
	if len(apiStatement.Conditions.MatchFamilies) > 0 {
		for _, family := range apiStatement.Conditions.MatchFamilies {
			s.Conditions.AfiSafiIn = append(s.Conditions.AfiSafiIn, toGoBGPFamily(family))
		}
	}

	// community actions
	if len(apiStatement.Actions.AddCommunities) > 0 {
		s.Actions.Community = &gobgp.CommunityAction{
			Type:        gobgp.CommunityAction_ADD,
			Communities: apiStatement.Actions.AddCommunities,
		}
	}
	if len(apiStatement.Actions.AddLargeCommunities) > 0 {
		s.Actions.LargeCommunity = &gobgp.CommunityAction{
			Type:        gobgp.CommunityAction_ADD,
			Communities: apiStatement.Actions.AddLargeCommunities,
		}
	}

	// local preference actions
	if apiStatement.Actions.SetLocalPreference != nil {
		// Local preference only makes sense for iBGP sessions. However, it can be applied
		// unconditionally here - it would have no effect on eBGP peers matching this policy.
		s.Actions.LocalPref = &gobgp.LocalPrefAction{
			Value: uint32(*apiStatement.Actions.SetLocalPreference),
		}
	}
	return s, definedSets
}

func toAgentPolicyStatement(s *gobgp.Statement, definedSets map[string]*gobgp.DefinedSet) *types.RoutePolicyStatement {
	stmt := &types.RoutePolicyStatement{}

	if s.Conditions != nil {
		if s.Conditions.NeighborSet != nil && definedSets[s.Conditions.NeighborSet.Name] != nil {
			stmt.Conditions.MatchNeighbors = definedSets[s.Conditions.NeighborSet.Name].List
		}
		if s.Conditions.PrefixSet != nil && definedSets[s.Conditions.PrefixSet.Name] != nil {
			for _, pfx := range definedSets[s.Conditions.PrefixSet.Name].Prefixes {
				cidr, err := netip.ParsePrefix(pfx.IpPrefix)
				if err == nil {
					stmt.Conditions.MatchPrefixes = append(stmt.Conditions.MatchPrefixes, &types.RoutePolicyPrefixMatch{
						CIDR:         cidr,
						PrefixLenMin: int(pfx.MaskLengthMin),
						PrefixLenMax: int(pfx.MaskLengthMax),
					})
				}
			}
		}
		for _, family := range s.Conditions.AfiSafiIn {
			stmt.Conditions.MatchFamilies = append(stmt.Conditions.MatchFamilies, toAgentFamily(family))
		}
	}
	if s.Actions != nil {
		stmt.Actions.RouteAction = toAgentRouteAction(s.Actions.RouteAction)
		if s.Actions.Community != nil {
			stmt.Actions.AddCommunities = s.Actions.Community.Communities
		}
		if s.Actions.LargeCommunity != nil {
			stmt.Actions.AddLargeCommunities = s.Actions.LargeCommunity.Communities
		}
		if s.Actions.LocalPref != nil {
			localPref := int64(s.Actions.LocalPref.Value)
			stmt.Actions.SetLocalPreference = &localPref
		}
	}
	return stmt
}

func policyStatementName(policyName string, cnt int) string {
	return fmt.Sprintf("%s-%d", policyName, cnt)
}

func policyNeighborDefinedSetName(policyStatementName string) string {
	return policyStatementName + "-neighbor"
}

func policyPrefixDefinedSetName(policyStatementName string) string {
	return policyStatementName + "-prefix"
}

func toGoBGPRouteAction(a types.RoutePolicyAction) gobgp.RouteAction {
	switch a {
	case types.RoutePolicyActionAccept:
		return gobgp.RouteAction_ACCEPT
	case types.RoutePolicyActionReject:
		return gobgp.RouteAction_REJECT
	}
	return gobgp.RouteAction_NONE
}

func toAgentRouteAction(a gobgp.RouteAction) types.RoutePolicyAction {
	switch a {
	case gobgp.RouteAction_ACCEPT:
		return types.RoutePolicyActionAccept
	case gobgp.RouteAction_REJECT:
		return types.RoutePolicyActionReject
	}
	return types.RoutePolicyActionNone
}

func toGoBGPPolicyDirection(policyType types.RoutePolicyType) gobgp.PolicyDirection {
	switch policyType {
	case types.RoutePolicyTypeExport:
		return gobgp.PolicyDirection_EXPORT
	case types.RoutePolicyTypeImport:
		return gobgp.PolicyDirection_IMPORT
	}
	return gobgp.PolicyDirection_UNKNOWN
}

func toAgentPolicyType(d gobgp.PolicyDirection) types.RoutePolicyType {
	if d == gobgp.PolicyDirection_IMPORT {
		return types.RoutePolicyTypeImport
	}
	return types.RoutePolicyTypeExport
}

func toGoBGPSoftResetDirection(direction types.SoftResetDirection) gobgp.ResetPeerRequest_SoftResetDirection {
	switch direction {
	case types.SoftResetDirectionIn:
		return gobgp.ResetPeerRequest_IN
	case types.SoftResetDirectionOut:
		return gobgp.ResetPeerRequest_OUT
	}
	return gobgp.ResetPeerRequest_BOTH
}

// toAgentSessionState translates gobgp session state to cilium bgp session state.
func toAgentSessionState(s gobgp.PeerState_SessionState) types.SessionState {
	switch s {
	case gobgp.PeerState_UNKNOWN:
		return types.SessionUnknown
	case gobgp.PeerState_IDLE:
		return types.SessionIdle
	case gobgp.PeerState_CONNECT:
		return types.SessionConnect
	case gobgp.PeerState_ACTIVE:
		return types.SessionActive
	case gobgp.PeerState_OPENSENT:
		return types.SessionOpenSent
	case gobgp.PeerState_OPENCONFIRM:
		return types.SessionOpenConfirm
	case gobgp.PeerState_ESTABLISHED:
		return types.SessionEstablished
	default:
		return types.SessionUnknown
	}
}

func toAgentFamily(family *gobgp.Family) types.Family {
	return types.Family{
		Afi:  toAgentAfi(family.Afi),
		Safi: toAgentSafi(family.Safi),
	}
}

// toAgentAfi translates gobgp AFI to cilium bgp AFI.
func toAgentAfi(a gobgp.Family_Afi) types.Afi {
	switch a {
	case gobgp.Family_AFI_UNKNOWN:
		return types.AfiUnknown
	case gobgp.Family_AFI_IP:
		return types.AfiIPv4
	case gobgp.Family_AFI_IP6:
		return types.AfiIPv6
	case gobgp.Family_AFI_L2VPN:
		return types.AfiL2VPN
	case gobgp.Family_AFI_LS:
		return types.AfiLS
	case gobgp.Family_AFI_OPAQUE:
		return types.AfiOpaque
	default:
		return types.AfiUnknown
	}
}

func toAgentSafi(s gobgp.Family_Safi) types.Safi {
	switch s {
	case gobgp.Family_SAFI_UNKNOWN:
		return types.SafiUnknown
	case gobgp.Family_SAFI_UNICAST:
		return types.SafiUnicast
	case gobgp.Family_SAFI_MULTICAST:
		return types.SafiMulticast
	case gobgp.Family_SAFI_MPLS_LABEL:
		return types.SafiMplsLabel
	case gobgp.Family_SAFI_ENCAPSULATION:
		return types.SafiEncapsulation
	case gobgp.Family_SAFI_VPLS:
		return types.SafiVpls
	case gobgp.Family_SAFI_EVPN:
		return types.SafiEvpn
	case gobgp.Family_SAFI_LS:
		return types.SafiLs
	case gobgp.Family_SAFI_SR_POLICY:
		return types.SafiSrPolicy
	case gobgp.Family_SAFI_MUP:
		return types.SafiMup
	case gobgp.Family_SAFI_MPLS_VPN:
		return types.SafiMplsVpn
	case gobgp.Family_SAFI_MPLS_VPN_MULTICAST:
		return types.SafiMplsVpnMulticast
	case gobgp.Family_SAFI_ROUTE_TARGET_CONSTRAINTS:
		return types.SafiRouteTargetConstraints
	case gobgp.Family_SAFI_FLOW_SPEC_UNICAST:
		return types.SafiFlowSpecUnicast
	case gobgp.Family_SAFI_FLOW_SPEC_VPN:
		return types.SafiFlowSpecVpn
	case gobgp.Family_SAFI_KEY_VALUE:
		return types.SafiKeyValue
	default:
		return types.SafiUnknown
	}
}

func toGoBGPTableType(t types.TableType) (gobgp.TableType, error) {
	switch t {
	case types.TableTypeLocRIB:
		return gobgp.TableType_LOCAL, nil
	case types.TableTypeAdjRIBIn:
		return gobgp.TableType_ADJ_IN, nil
	case types.TableTypeAdjRIBOut:
		return gobgp.TableType_ADJ_OUT, nil
	default:
		return gobgp.TableType_LOCAL, fmt.Errorf("unknown table type %d", t)
	}
}
