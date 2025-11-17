// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	MaxPrefixLenIPv4 = 32
	MaxPrefixLenIPv6 = 128
)

// ResourceRoutePolicyMap holds the route policies per resource.
type ResourceRoutePolicyMap map[resource.Key]RoutePolicyMap

// RoutePolicyMap holds routing policies configured by the policy reconciler keyed by policy name.
type RoutePolicyMap map[string]*types.RoutePolicy

type ReconcileRoutePoliciesParams struct {
	Logger          *slog.Logger
	Ctx             context.Context
	Router          types.Router
	DesiredPolicies RoutePolicyMap
	CurrentPolicies RoutePolicyMap
}

type resetDirections struct {
	in  bool
	out bool
}

func (rd *resetDirections) Update(dir types.RoutePolicyType) {
	switch dir {
	case types.RoutePolicyTypeExport:
		rd.out = true
	case types.RoutePolicyTypeImport:
		rd.in = true
	}
}

func (rd *resetDirections) SoftResetDirection() types.SoftResetDirection {
	if rd.in && rd.out {
		return types.SoftResetDirectionBoth
	} else if rd.in {
		return types.SoftResetDirectionIn
	} else if rd.out {
		return types.SoftResetDirectionOut
	}
	return types.SoftResetDirectionNone
}

// ReconcileRoutePolicies reconciles routing policies between the desired and the current state.
// It returns the updated routing policies and an error if the reconciliation fails.
func ReconcileRoutePolicies(rp *ReconcileRoutePoliciesParams) (RoutePolicyMap, error) {
	runningPolicies := make(RoutePolicyMap)
	maps.Copy(runningPolicies, rp.CurrentPolicies)

	var toAdd, toRemove, toUpdate []*types.RoutePolicy

	// Tracks which peers have to be reset which direction because of policy change
	resetPeers := map[netip.Addr]*resetDirections{}
	allResetDirs := &resetDirections{}

	upsertResetPeers := func(p *types.RoutePolicy) {
		addrs, allPeers := peerAddressesFromPolicy(p)
		if allPeers {
			allResetDirs.Update(p.Type)
			return
		}
		for _, peer := range addrs {
			dirs, found := resetPeers[peer]
			if !found {
				dirs = &resetDirections{}
			}
			dirs.Update(p.Type)
			resetPeers[peer] = dirs
		}
	}

	for _, desired := range rp.DesiredPolicies {
		if current, found := rp.CurrentPolicies[desired.Name]; found {
			if !current.DeepEqual(desired) {
				toUpdate = append(toUpdate, desired)

				// This can be optimized further by checking whether the update
				// is only for the list of neighbors. In that case, the peers in
				// the old policy would not need a reset. At this point, we
				// blindly reset all peers in the old policy for simplicity.
				upsertResetPeers(desired)
				upsertResetPeers(current)
			}
		} else {
			toAdd = append(toAdd, desired)
			upsertResetPeers(desired)
		}
	}
	for _, current := range rp.CurrentPolicies {
		if _, found := rp.DesiredPolicies[current.Name]; !found {
			toRemove = append(toRemove, current)
			upsertResetPeers(current)
		}
	}

	// add missing policies
	for _, p := range toAdd {
		rp.Logger.Debug(
			"Adding route policy",
			types.PolicyLogField, p.Name,
		)

		err := rp.Router.AddRoutePolicy(rp.Ctx, types.RoutePolicyRequest{
			DefaultExportAction: types.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
	}

	// update modified policies
	for _, p := range toUpdate {
		// As proper implementation of an update operation for complex policies would be quite involved,
		// we resort to recreating the policies that need an update here.
		rp.Logger.Debug(
			"Updating (re-creating) route policy",
			types.PolicyLogField, p.Name,
		)

		existing := rp.CurrentPolicies[p.Name]
		err := rp.Router.RemoveRoutePolicy(rp.Ctx, types.RoutePolicyRequest{Policy: existing})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, existing.Name)

		err = rp.Router.AddRoutePolicy(rp.Ctx, types.RoutePolicyRequest{
			DefaultExportAction: types.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
	}

	// remove old policies
	for _, p := range toRemove {
		rp.Logger.Debug(
			"Removing route policy",
			types.PolicyLogField, p.Name,
		)

		err := rp.Router.RemoveRoutePolicy(rp.Ctx, types.RoutePolicyRequest{Policy: p})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, p.Name)
	}

	// If we have all reset, process it first
	if allResetDirs.SoftResetDirection() != types.SoftResetDirectionNone {
		rp.Logger.Debug(
			"Resetting all peers due to a routing policy change",
			types.DirectionLogField, allResetDirs.SoftResetDirection().String(),
		)

		req := types.ResetAllNeighborsRequest{
			Soft:               true,
			SoftResetDirection: allResetDirs.SoftResetDirection(),
		}

		if err := rp.Router.ResetAllNeighbors(rp.Ctx, req); err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.Debug(
				"resetting all peers failed after a routing policy change",
				logfields.Error, err,
				types.DirectionLogField, allResetDirs.SoftResetDirection().String(),
			)
		}
	}

	// Handle individual neighbor resets
	// soft-reset affected BGP peers to apply the changes on already advertised routes
	for peer, dirs := range resetPeers {
		// Skip if we already did all reset for this exact direction
		if allResetDirs.SoftResetDirection() == dirs.SoftResetDirection() {
			continue
		}
		// Skip if we did all reset for both directions (covers this peer)
		if allResetDirs.SoftResetDirection() == types.SoftResetDirectionBoth {
			continue
		}
		rp.Logger.Debug(
			"Resetting peer due to a routing policy change",
			types.PeerLogField, peer,
			types.DirectionLogField, dirs.SoftResetDirection().String(),
		)

		req := types.ResetNeighborRequest{
			PeerAddress:        peer,
			Soft:               true,
			SoftResetDirection: dirs.SoftResetDirection(),
		}

		if err := rp.Router.ResetNeighbor(rp.Ctx, req); err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.Debug(
				"resetting peer failed after a routing policy change",
				logfields.Error, err,
				types.PeerLogField, peer,
				types.DirectionLogField, dirs.SoftResetDirection().String(),
			)
		}
	}

	return runningPolicies, nil
}

// PolicyName returns a unique route policy name for the provided peer, family and advertisement type.
// If there a is a need for multiple route policies per advertisement type, unique resourceID can be provided.
func PolicyName(peer, family string, advertType v2.BGPAdvertisementType, resourceID string) string {
	if resourceID == "" {
		return fmt.Sprintf("%s-%s-%s", peer, family, advertType)
	}
	return fmt.Sprintf("%s-%s-%s-%s", peer, family, advertType, resourceID)
}

func CreatePolicy(name string, peerAddr netip.Addr, v4Prefixes, v6Prefixes types.PolicyPrefixList, advert v2.BGPAdvertisement) (*types.RoutePolicy, error) {
	policy := &types.RoutePolicy{
		Name: name,
		Type: types.RoutePolicyTypeExport,
	}

	// sort prefixes to have consistent order for DeepEqual
	sort.Slice(v4Prefixes, v4Prefixes.Less)
	sort.Slice(v6Prefixes, v6Prefixes.Less)

	// get communities
	communities, largeCommunities, err := getCommunities(advert)
	if err != nil {
		return nil, err
	}

	// get local preference
	var localPref *int64
	if advert.Attributes != nil {
		localPref = advert.Attributes.LocalPreference
	}

	// Due to a GoBGP limitation, we need to generate a separate statement for v4 and v6 prefixes, as families
	// can not be mixed in a single statement. Nevertheless, they can be both part of the same Policy.
	if len(v4Prefixes) > 0 {
		policy.Statements = append(policy.Statements, policyStatement(peerAddr, v4Prefixes, localPref, communities, largeCommunities))
	}
	if len(v6Prefixes) > 0 {
		policy.Statements = append(policy.Statements, policyStatement(peerAddr, v6Prefixes, localPref, communities, largeCommunities))
	}

	return policy, nil
}

// MergeRoutePolicies evaluates two instances of RoutePolicy{} and returns a single RoutePolicy{} representing
// the merger of the two.  The merge operation focuses on each policy's Statements.  Statements define one or more
// Actions, and these actions may include setting BGP Communities, Local Preference, and others.  Statements are
// keyed by their Conditions, which define the BGP Neighbor, AF, and Prefixes it applies to.
//
// The merge operation evaluates Actions across only those statements with the same key. For these Statements,
// the merge takes the union of all BGP Communities set.  When differing Local Preference values are set, the
// higher value is selected.
func MergeRoutePolicies(policyA *types.RoutePolicy, policyB *types.RoutePolicy) (*types.RoutePolicy, error) {
	if policyA == nil || policyB == nil {
		return nil, fmt.Errorf("route policy is nil")
	}
	if policyA.Name != policyB.Name {
		return nil, fmt.Errorf("route policy names do not match")
	}
	if policyA.Type != policyB.Type {
		return nil, fmt.Errorf("route policy types do not match")
	}

	mergedPolicy := &types.RoutePolicy{
		Name:       policyA.Name,
		Type:       policyA.Type,
		Statements: []*types.RoutePolicyStatement{},
	}

	// Maps a string key representing the unique combination of RoutePolicyConditions{} to a RoutePolicyStatement{}.
	// When multiple instances of the same key are observed, the existing RoutePolicyStatement{} will be updated to
	// reflect the union of attributes set.
	mergedPolicyStatements := map[string]*types.RoutePolicyStatement{}

	// Extract the first policy's statements and attributes
	mergedPolicyStatements = mergePolicy(policyA, mergedPolicyStatements)

	// Extract and merge the second policy's statements and attributes
	mergedPolicyStatements = mergePolicy(policyB, mergedPolicyStatements)

	for _, mergedStatement := range mergedPolicyStatements {
		mergedPolicy.Statements = append(mergedPolicy.Statements, mergedStatement)
	}

	// Deduplicate communities
	for _, statement := range mergedPolicy.Statements {
		if len(statement.Actions.AddCommunities) != 0 {
			uniqueCommunities := sets.NewString(statement.Actions.AddCommunities...).List()
			statement.Actions.AddCommunities = uniqueCommunities
		}
		if len(statement.Actions.AddLargeCommunities) != 0 {
			uniqueLargeCommunities := sets.NewString(statement.Actions.AddLargeCommunities...).List()
			statement.Actions.AddLargeCommunities = uniqueLargeCommunities
		}
	}

	// Sort statements based on prefix length:
	// - Statements with greater prefix length should go first, so that longer prefix match has higher priority.
	//   Main use-case is service route aggregation, where a single svc can have e.g. /32 and /24 match statements,
	//   and the /32 one should be prioritized.
	// - For simplicity, we only compare the length of the first prefix, as we never populate different prefix lengths
	//   in a single condition. PrefixLenMin and PrefixLenMax are always populated equally, so we only compare one of them.
	sort.SliceStable(mergedPolicy.Statements, func(i, j int) bool {
		condI := mergedPolicy.Statements[i].Conditions
		condJ := mergedPolicy.Statements[j].Conditions
		if condI.MatchPrefixes != nil && condJ.MatchPrefixes != nil &&
			len(condI.MatchPrefixes.Prefixes) > 0 && len(condJ.MatchPrefixes.Prefixes) > 0 {
			return condI.MatchPrefixes.Prefixes[0].PrefixLenMin > condJ.MatchPrefixes.Prefixes[0].PrefixLenMin
		}
		return false
	})

	return mergedPolicy, nil
}

func mergePolicy(
	policy *types.RoutePolicy,
	inputPolicyStatements map[string]*types.RoutePolicyStatement,
) (outputPolicyStatements map[string]*types.RoutePolicyStatement) {

	// This function aims to be purely functional.  Here, we are creating a copy of the input to hold the result
	// of the merge operation.
	outputPolicyStatements = map[string]*types.RoutePolicyStatement{}
	maps.Copy(outputPolicyStatements, inputPolicyStatements)

	for _, statement := range policy.Statements {
		key := statement.Conditions.String()
		if _, found := outputPolicyStatements[key]; !found {
			outputPolicyStatements[key] = &types.RoutePolicyStatement{
				Actions:    statement.Actions,
				Conditions: statement.Conditions,
			}
		} else {
			if len(statement.Actions.AddCommunities) > 0 {
				outputPolicyStatements[key].Actions.AddCommunities = append(
					outputPolicyStatements[key].Actions.AddCommunities, statement.Actions.AddCommunities...)
			}
			if len(statement.Actions.AddLargeCommunities) > 0 {
				outputPolicyStatements[key].Actions.AddLargeCommunities = append(
					outputPolicyStatements[key].Actions.AddLargeCommunities, statement.Actions.AddLargeCommunities...)
			}

			// RFC 4271 states "The higher degree of preference MUST be preferred."
			if statement.Actions.SetLocalPreference != nil {
				if outputPolicyStatements[key].Actions.SetLocalPreference == nil {
					// This is the first with Local Preference set
					outputPolicyStatements[key].Actions.SetLocalPreference = statement.Actions.SetLocalPreference
				} else if *statement.Actions.SetLocalPreference > *outputPolicyStatements[key].Actions.SetLocalPreference {
					// This statement's Local Preference is better than the previous best, use this one.
					outputPolicyStatements[key].Actions.SetLocalPreference = statement.Actions.SetLocalPreference
				}
			}
		}
	}

	return outputPolicyStatements
}

func getCommunities(advert v2.BGPAdvertisement) (standard, large []string, err error) {
	standard, err = mergeAndDedupCommunities(advert)
	if err != nil {
		return nil, nil, err
	}
	large = dedupLargeCommunities(advert)

	return standard, large, nil
}

// mergeAndDedupCommunities merges numeric standard community and well-known community strings,
// deduplicated by their actual community values.
func mergeAndDedupCommunities(advert v2.BGPAdvertisement) ([]string, error) {
	var res []string

	if advert.Attributes == nil || advert.Attributes.Communities == nil {
		return res, nil
	}

	standard := advert.Attributes.Communities.Standard
	wellKnown := advert.Attributes.Communities.WellKnown

	existing := sets.New[uint32]()
	for _, c := range standard {
		val, err := parseCommunity(string(c))
		if err != nil {
			return nil, fmt.Errorf("failed to parse standard BGP community: %w", err)
		}
		if existing.Has(val) {
			continue
		}
		existing.Insert(val)
		res = append(res, string(c))
	}

	for _, c := range wellKnown {
		val, ok := bgp.WellKnownCommunityValueMap[string(c)]
		if !ok {
			return nil, fmt.Errorf("invalid well-known community value '%s'", c)
		}
		if existing.Has(uint32(val)) {
			continue
		}
		existing.Insert(uint32(val))
		res = append(res, string(c))
	}
	return res, nil
}

func parseCommunity(communityStr string) (uint32, error) {
	// parse as <0-65535>:<0-65535>
	if elems := strings.Split(communityStr, ":"); len(elems) == 2 {
		fst, err := strconv.ParseUint(elems[0], 10, 16)
		if err != nil {
			return 0, err
		}
		snd, err := strconv.ParseUint(elems[1], 10, 16)
		if err != nil {
			return 0, err
		}
		return uint32(fst<<16 | snd), nil
	}
	// parse as a single decimal number
	c, err := strconv.ParseUint(communityStr, 10, 32)
	return uint32(c), err
}

// dedupLargeCommunities returns deduplicated large communities as a string slice.
func dedupLargeCommunities(advert v2.BGPAdvertisement) []string {
	var res []string

	if advert.Attributes == nil || advert.Attributes.Communities == nil {
		return res
	}

	communities := advert.Attributes.Communities.Large

	existing := sets.New[string]()
	for _, c := range communities {
		if existing.Has(string(c)) {
			continue
		}
		existing.Insert(string(c))
		res = append(res, string(c))
	}
	return res
}

func policyStatement(neighborAddr netip.Addr, prefixes types.PolicyPrefixList, localPref *int64, communities, largeCommunities []string) *types.RoutePolicyStatement {
	return &types.RoutePolicyStatement{
		Conditions: types.RoutePolicyConditions{
			MatchNeighbors: &types.RoutePolicyNeighborMatch{
				Type:      types.RoutePolicyMatchAny,
				Neighbors: []netip.Addr{neighborAddr},
			},
			MatchPrefixes: &types.RoutePolicyPrefixMatch{
				Type:     types.RoutePolicyMatchAny,
				Prefixes: prefixes,
			},
		},
		Actions: types.RoutePolicyActions{
			RouteAction:         types.RoutePolicyActionAccept,
			SetLocalPreference:  localPref,
			AddCommunities:      communities,
			AddLargeCommunities: largeCommunities,
		},
	}
}

// peerAddressesFromPolicy returns neighbor addresses found in a routing policy.
// It returns true when the policy contains the empty MatchNeighbors which means
// all neighbors.
func peerAddressesFromPolicy(p *types.RoutePolicy) ([]netip.Addr, bool) {
	if p == nil {
		return []netip.Addr{}, false
	}
	addrs := []netip.Addr{}
	allPeers := false
	for _, s := range p.Statements {
		if s.Conditions.MatchNeighbors == nil || len(s.Conditions.MatchNeighbors.Neighbors) == 0 {
			allPeers = true
		} else {
			addrs = append(addrs, s.Conditions.MatchNeighbors.Neighbors...)
		}
	}
	return addrs, allPeers
}
