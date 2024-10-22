// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
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
	Logger          logrus.FieldLogger
	Ctx             context.Context
	Router          types.Router
	DesiredPolicies RoutePolicyMap
	CurrentPolicies RoutePolicyMap
}

// ReconcileRoutePolicies reconciles routing policies between the desired and the current state.
// It returns the updated routing policies and an error if the reconciliation fails.
func ReconcileRoutePolicies(rp *ReconcileRoutePoliciesParams) (RoutePolicyMap, error) {
	runningPolicies := make(RoutePolicyMap)
	maps.Copy(runningPolicies, rp.CurrentPolicies)

	var toAdd, toRemove, toUpdate []*types.RoutePolicy

	for _, p := range rp.DesiredPolicies {
		if existing, found := rp.CurrentPolicies[p.Name]; found {
			if !existing.DeepEqual(p) {
				toUpdate = append(toUpdate, p)
			}
		} else {
			toAdd = append(toAdd, p)
		}
	}
	for _, p := range rp.CurrentPolicies {
		if _, found := rp.DesiredPolicies[p.Name]; !found {
			toRemove = append(toRemove, p)
		}
	}

	// tracks which peers have to be reset because of policy change
	resetPeers := sets.New[string]()

	// add missing policies
	for _, p := range toAdd {
		rp.Logger.WithFields(logrus.Fields{
			types.PolicyLogField: p.Name,
		}).Debug("Adding route policy")

		err := rp.Router.AddRoutePolicy(rp.Ctx, types.RoutePolicyRequest{
			DefaultExportAction: types.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
		resetPeers.Insert(peerAddressFromPolicy(p))
	}

	// update modified policies
	for _, p := range toUpdate {
		// As proper implementation of an update operation for complex policies would be quite involved,
		// we resort to recreating the policies that need an update here.
		rp.Logger.WithFields(logrus.Fields{
			types.PolicyLogField: p.Name,
		}).Debug("Updating (re-creating) route policy")

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
		resetPeers.Insert(peerAddressFromPolicy(p))
	}

	// remove old policies
	for _, p := range toRemove {
		rp.Logger.WithFields(logrus.Fields{
			types.PolicyLogField: p.Name,
		}).Debug("Removing route policy")

		err := rp.Router.RemoveRoutePolicy(rp.Ctx, types.RoutePolicyRequest{Policy: p})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, p.Name)
		resetPeers.Insert(peerAddressFromPolicy(p))
	}

	// soft-reset affected BGP peers to apply the changes on already advertised routes
	for peer := range resetPeers {
		_, err := netip.ParsePrefix(peer)
		if err != nil {
			continue
		}

		rp.Logger.WithFields(logrus.Fields{
			types.PeerLogField: peer,
		}).Debug("Resetting peer due to a routing policy change")

		req := types.ResetNeighborRequest{
			PeerAddress:        peer,
			Soft:               true,
			SoftResetDirection: types.SoftResetDirectionOut, // we are using only export policies
		}

		err = rp.Router.ResetNeighbor(rp.Ctx, req)
		if err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.WithFields(logrus.Fields{
				types.PeerLogField: peer,
			}).WithError(err).Debug("resetting peer failed after a routing policy change")
		}
	}

	return runningPolicies, nil
}

// PolicyName returns a unique route policy name for the provided peer, family and advertisement type.
// If there a is a need for multiple route policies per advertisement type, unique resourceID can be provided.
func PolicyName(peer, family string, advertType v2alpha1.BGPAdvertisementType, resourceID string) string {
	if resourceID == "" {
		return fmt.Sprintf("%s-%s-%s", peer, family, advertType)
	}
	return fmt.Sprintf("%s-%s-%s-%s", peer, family, advertType, resourceID)
}

func CreatePolicy(name string, peerAddr netip.Addr, v4Prefixes, v6Prefixes types.PolicyPrefixMatchList, advert v2alpha1.BGPAdvertisement) (*types.RoutePolicy, error) {
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

func getCommunities(advert v2alpha1.BGPAdvertisement) (standard, large []string, err error) {
	standard, err = mergeAndDedupCommunities(advert)
	if err != nil {
		return nil, nil, err
	}
	large = dedupLargeCommunities(advert)

	return standard, large, nil
}

// mergeAndDedupCommunities merges numeric standard community and well-known community strings,
// deduplicated by their actual community values.
func mergeAndDedupCommunities(advert v2alpha1.BGPAdvertisement) ([]string, error) {
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
func dedupLargeCommunities(advert v2alpha1.BGPAdvertisement) []string {
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

func policyStatement(neighborAddr netip.Addr, prefixes []*types.RoutePolicyPrefixMatch, localPref *int64, communities, largeCommunities []string) *types.RoutePolicyStatement {
	// create /32 or /128 neighbor prefix match
	neighborPrefix := netip.PrefixFrom(neighborAddr, neighborAddr.BitLen())

	return &types.RoutePolicyStatement{
		Conditions: types.RoutePolicyConditions{
			MatchNeighbors: []string{neighborPrefix.String()},
			MatchPrefixes:  prefixes,
		},
		Actions: types.RoutePolicyActions{
			RouteAction:         types.RoutePolicyActionAccept,
			SetLocalPreference:  localPref,
			AddCommunities:      communities,
			AddLargeCommunities: largeCommunities,
		},
	}
}

// peerAddressFromPolicy returns the first neighbor address found in a routing policy.
func peerAddressFromPolicy(p *types.RoutePolicy) string {
	if p == nil {
		return ""
	}
	for _, s := range p.Statements {
		for _, m := range s.Conditions.MatchNeighbors {
			return m
		}
	}
	return ""
}
