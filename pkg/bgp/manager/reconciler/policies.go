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

	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"k8s.io/apimachinery/pkg/util/sets"

	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ResourceDesiredRoutePolicyMap holds the route policy statements per resource.
type ResourceDesiredRoutePolicyMap map[resource.Key][]*bgpTables.DesiredRoutePolicy

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

// PolicyStatementName returns a route policy statement name for the provided advertisement type.
// If there is a need for multiple route policies per advertisement type, unique resourceID can be provided.
func PolicyStatementName(advertType v2.BGPAdvertisementType, resourceID string) string {
	if resourceID == "" {
		return string(advertType)
	}
	return fmt.Sprintf("%s-%s", advertType, resourceID)
}

func CreatePolicyStatements(namePrefix string, peerAddr netip.Addr, v4Prefixes, v6Prefixes types.PolicyPrefixList, advert v2.BGPAdvertisement) ([]*types.RoutePolicyStatement, error) {
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

	statements := []*types.RoutePolicyStatement{}

	// Due to a GoBGP limitation, we need to generate a separate statement for v4 and v6 prefixes, as families
	// can not be mixed in a single statement. Nevertheless, they can be both part of the same Policy.
	if len(v4Prefixes) > 0 {
		statements = append(statements, policyStatement(namePrefix+"-ipv4", peerAddr, v4Prefixes, localPref, communities, largeCommunities))
	}
	if len(v6Prefixes) > 0 {
		statements = append(statements, policyStatement(namePrefix+"-ipv6", peerAddr, v6Prefixes, localPref, communities, largeCommunities))
	}
	return statements, nil
}

// mergeRoutePolicyStatements merges two policy statements of the same Name, Conditions and RouteAction,
// that usually belong to the same resource, but were rendered by different advertisements.
// Different advertisements can contain various path attributes, so deduplicate and merge them here:
//   - create union of all BGP Communities,
//   - for differing Local Preference values, select the higher value.
func mergeRoutePolicyStatements(statementA, statementB *types.RoutePolicyStatement) (*types.RoutePolicyStatement, error) {
	if statementA.Name != statementB.Name {
		return nil, fmt.Errorf("route policy statement names do not match")
	}
	if !statementA.Conditions.DeepEqual(&statementB.Conditions) {
		return nil, fmt.Errorf("route policy statement conditions do not match")
	}
	if statementA.Actions.RouteAction != statementB.Actions.RouteAction {
		return nil, fmt.Errorf("route policy statement route actions do not match")
	}

	merged := &types.RoutePolicyStatement{
		Name:       statementA.Name,
		Conditions: statementA.Conditions,
		Actions: types.RoutePolicyActions{
			RouteAction:         statementA.Actions.RouteAction,
			AddCommunities:      mergeCommunities(statementA.Actions.AddCommunities, statementB.Actions.AddCommunities),
			AddLargeCommunities: mergeCommunities(statementA.Actions.AddLargeCommunities, statementB.Actions.AddLargeCommunities),
			NextHop:             statementA.Actions.NextHop,
		},
	}

	// RFC 4271 states "The higher degree of preference MUST be preferred."
	merged.Actions.SetLocalPreference = statementA.Actions.SetLocalPreference
	if statementB.Actions.SetLocalPreference != nil {
		if merged.Actions.SetLocalPreference == nil || *statementB.Actions.SetLocalPreference > *merged.Actions.SetLocalPreference {
			merged.Actions.SetLocalPreference = statementB.Actions.SetLocalPreference
		}
	}
	return merged, nil
}

func mergeCommunities(communitiesA, communitiesB []string) []string {
	if len(communitiesA) == 0 && len(communitiesB) == 0 {
		return nil
	}
	set := sets.NewString(communitiesA...)
	set.Insert(communitiesB...)
	return set.List()
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

func policyStatement(name string, neighborAddr netip.Addr, prefixes types.PolicyPrefixList, localPref *int64, communities, largeCommunities []string) *types.RoutePolicyStatement {
	return &types.RoutePolicyStatement{
		Name: name,
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

// reconcileDesiredRoutePolicyStatements ensures that the DesiredRoutePolicy table contains provided desiredStatements
// for the given instance + owner + resource combination.
func reconcileDesiredRoutePolicyStatements(tx statedb.WriteTxn, table statedb.RWTable[*bgpTables.DesiredRoutePolicy],
	instance string, owner string, resource resource.Key, desiredStatements []*bgpTables.DesiredRoutePolicy) error {

	desiredByKey := make(map[bgpTables.DesiredRoutePolicyKey]*bgpTables.DesiredRoutePolicy, len(desiredStatements))
	for _, statement := range desiredStatements {
		desiredByKey[statement.GetKey()] = statement
	}

	existingByKey := make(map[bgpTables.DesiredRoutePolicyKey]*bgpTables.DesiredRoutePolicy)
	for existing := range table.List(tx, bgpTables.DesiredRoutePoliciesByInstanceOwnerResource(instance, owner, resource)) {
		existingByKey[existing.GetKey()] = existing
	}

	// delete stale statements
	for key, existing := range existingByKey {
		if _, isDesired := desiredByKey[key]; !isDesired {
			if _, _, err := table.Delete(tx, existing); err != nil {
				return fmt.Errorf("error deleting desired route policy statement %s: %w", key.StatementName, err)
			}
		}
	}

	// insert new / update existing statements
	for key, desired := range desiredByKey {
		existing, exists := existingByKey[key]
		if exists && existing.DeepEqual(desired) {
			continue
		}
		if _, _, err := table.Insert(tx, desired); err != nil {
			return fmt.Errorf("error inserting desired route policy statement %s: %w", key.StatementName, err)
		}
	}

	return nil
}

// cleanupDesiredRoutePolicyStatements removes statements with the provided instance + owner combination from the DesiredRoutePolicy table.
func cleanupDesiredRoutePolicyStatements(db *statedb.DB, table statedb.RWTable[*bgpTables.DesiredRoutePolicy], instanceName string, owner string) error {
	tx := db.WriteTxn(table)
	defer tx.Abort()

	for existing := range table.List(tx, bgpTables.DesiredRoutePoliciesByInstanceOwner(instanceName, owner)) {
		if _, _, err := table.Delete(tx, existing); err != nil {
			return fmt.Errorf("error deleting desired route policy statement %s: %w", existing.StatementName(), err)
		}
	}
	tx.Commit()
	return nil
}
