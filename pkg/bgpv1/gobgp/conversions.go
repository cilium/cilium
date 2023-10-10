// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"errors"
	"fmt"

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

	family := &gobgp.Family{
		Afi:  gobgp.Family_Afi(p.NLRI.AFI()),
		Safi: gobgp.Family_Safi(p.NLRI.SAFI()),
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

func policyStatementName(policyName string, cnt int) string {
	return fmt.Sprintf("%s-%d", policyName, cnt)
}

func policyNeighborDefinedSetName(policyStatementName string) string {
	return fmt.Sprintf(policyStatementName + "-neighbor")
}

func policyPrefixDefinedSetName(policyStatementName string) string {
	return fmt.Sprintf(policyStatementName + "-prefix")
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

func toGoBGPPolicyDirection(policyType types.RoutePolicyType) gobgp.PolicyDirection {
	switch policyType {
	case types.RoutePolicyTypeExport:
		return gobgp.PolicyDirection_EXPORT
	case types.RoutePolicyTypeImport:
		return gobgp.PolicyDirection_IMPORT
	}
	return gobgp.PolicyDirection_UNKNOWN
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
