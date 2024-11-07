// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	maxPrefixLenIPv4 = 32
	maxPrefixLenIPv6 = 128
)

type RoutePolicyReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type RoutePolicyReconciler struct {
	lbPoolStore  store.BGPCPResourceStore[*v2alpha1api.CiliumLoadBalancerIPPool]
	podPoolStore store.BGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]
}

// RoutePolicyReconcilerMetadata holds routing policies configured by the policy reconciler keyed by policy name.
type RoutePolicyReconcilerMetadata map[string]*types.RoutePolicy

func NewRoutePolicyReconciler(
	lbStore store.BGPCPResourceStore[*v2alpha1api.CiliumLoadBalancerIPPool],
	podStore store.BGPCPResourceStore[*v2alpha1api.CiliumPodIPPool],
) RoutePolicyReconcilerOut {
	return RoutePolicyReconcilerOut{
		Reconciler: &RoutePolicyReconciler{
			lbPoolStore:  lbStore,
			podPoolStore: podStore,
		},
	}
}

func (r *RoutePolicyReconciler) Name() string {
	return "RoutePolicy"
}

func (r *RoutePolicyReconciler) Priority() int {
	// Should reconcile after the NeighborReconciler (so have higher priority number),
	// as neighbor resets are performed from this reconciler.
	// This is not a hard requirement, just to avoid some warnings.
	return 70
}

func (r *RoutePolicyReconciler) Init(_ *instance.ServerWithConfig) error {
	return nil
}

func (r *RoutePolicyReconciler) Cleanup(_ *instance.ServerWithConfig) {}

func (r *RoutePolicyReconciler) Reconcile(ctx context.Context, params ReconcileParams) error {
	l := log.WithFields(logrus.Fields{"component": "RoutePolicyReconciler"})

	if params.DesiredConfig == nil {
		return fmt.Errorf("attempted routing policy reconciliation with nil DesiredConfig")
	}
	if params.CurrentServer == nil {
		return fmt.Errorf("attempted routing policy reconciliation with nil ServerWithConfig")
	}
	if params.CiliumNode == nil {
		return fmt.Errorf("attempted routing policy reconciliation with nil local CiliumNode")
	}

	// take currently configured policies from cache
	currentPolicies := r.getMetadata(params.CurrentServer)

	// compile set of desired policies
	// note: only per-neighbor export policies are supported at this time
	desiredPolicies := make(map[string]*types.RoutePolicy)
	for _, n := range params.DesiredConfig.Neighbors {
		for _, routeAttrs := range n.AdvertisedPathAttributes {
			exportPolicy, err := r.pathAttributesToPolicy(routeAttrs, n.PeerAddress, params)
			if err != nil {
				return fmt.Errorf("failed to convert BGP PathAttributes to a RoutePolicy: %w", err)
			}
			if len(exportPolicy.Statements) > 0 {
				desiredPolicies[exportPolicy.Name] = exportPolicy
			}
		}
	}

	var toAdd, toRemove, toUpdate []*types.RoutePolicy

	for _, p := range desiredPolicies {
		if existing, found := currentPolicies[p.Name]; found {
			if !existing.DeepEqual(p) {
				toUpdate = append(toUpdate, p)
			}
		} else {
			toAdd = append(toAdd, p)
		}
	}
	for _, p := range currentPolicies {
		if _, found := desiredPolicies[p.Name]; !found {
			toRemove = append(toRemove, p)
		}
	}

	resetPeers := make(map[string]bool)

	// add missing policies
	for _, p := range toAdd {
		l.Infof("Adding route policy %s to vrouter %d", p.Name, params.DesiredConfig.LocalASN)
		err := params.CurrentServer.Server.AddRoutePolicy(ctx, types.RoutePolicyRequest{
			DefaultExportAction: types.RoutePolicyActionNone, // no change to the default action
			Policy:              p,
		})
		if err != nil {
			return fmt.Errorf("failed adding route policy %v to vrouter %d: %w", p.Name, params.DesiredConfig.LocalASN, err)
		}
		resetPeers[peerAddressFromPolicy(p)] = true
	}
	// update modified policies
	for _, p := range toUpdate {
		// As proper implementation of an update operation for complex policies would be quite involved,
		// we resort to recreating the policies that need an update here.
		l.Infof("Updating (re-creating) route policy %s in vrouter %d", p.Name, params.DesiredConfig.LocalASN)
		existing := currentPolicies[p.Name]
		err := params.CurrentServer.Server.RemoveRoutePolicy(ctx, types.RoutePolicyRequest{Policy: existing})
		if err != nil {
			return fmt.Errorf("failed removing route policy %v from vrouter %d: %w", existing.Name, params.DesiredConfig.LocalASN, err)
		}
		err = params.CurrentServer.Server.AddRoutePolicy(ctx, types.RoutePolicyRequest{
			DefaultExportAction: types.RoutePolicyActionNone, // no change to the default action
			Policy:              p,
		})
		if err != nil {
			return fmt.Errorf("failed adding route policy %v to vrouter %d: %w", p.Name, params.DesiredConfig.LocalASN, err)
		}
		resetPeers[peerAddressFromPolicy(p)] = true
	}
	// remove old policies
	for _, p := range toRemove {
		l.Infof("Removing route policy %s from vrouter %d", p.Name, params.DesiredConfig.LocalASN)
		err := params.CurrentServer.Server.RemoveRoutePolicy(ctx, types.RoutePolicyRequest{Policy: p})
		if err != nil {
			return fmt.Errorf("failed removing route policy %v from vrouter %d: %w", p.Name, params.DesiredConfig.LocalASN, err)
		}
		resetPeers[peerAddressFromPolicy(p)] = true
	}

	// soft-reset affected BGP peers to apply the changes on already advertised routes
	for peer := range resetPeers {
		l.Infof("Resetting peer %s on vrouter %d due to a routing policy change", peer, params.DesiredConfig.LocalASN)
		req := types.ResetNeighborRequest{
			PeerAddress:        peer,
			Soft:               true,
			SoftResetDirection: types.SoftResetDirectionOut, // we are using only export policies
		}
		err := params.CurrentServer.Server.ResetNeighbor(ctx, req)
		if err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			l.Warnf("error by resetting peer %s after a routing policy change: %v", peer, err)
		}
	}

	// reconciliation successful, update the cache of configured policies which is now equal to desired polices
	r.storeMetadata(params.CurrentServer, desiredPolicies)
	return nil
}

func (r *RoutePolicyReconciler) getMetadata(sc *instance.ServerWithConfig) RoutePolicyReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(RoutePolicyReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(RoutePolicyReconcilerMetadata)
}

func (r *RoutePolicyReconciler) storeMetadata(sc *instance.ServerWithConfig, meta RoutePolicyReconcilerMetadata) {
	sc.ReconcilerMetadata[r.Name()] = meta
}

// pathAttributesToPolicy prepares an export policy configured by CRD using the Advertised Path Attributes feature
func (r *RoutePolicyReconciler) pathAttributesToPolicy(attrs v2alpha1api.CiliumBGPPathAttributes, neighborAddress string, params ReconcileParams) (*types.RoutePolicy, error) {
	var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList

	policy := &types.RoutePolicy{
		Name: pathAttributesPolicyName(attrs, neighborAddress),
		Type: types.RoutePolicyTypeExport,
	}

	labelSelector, err := slim_metav1.LabelSelectorAsSelector(attrs.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed constructing LabelSelector: %w", err)
	}

	switch attrs.SelectorType {
	case v2alpha1api.CPIPKindDefinition:
		localPools := r.populateLocalPools(params.CiliumNode)
		podPoolList, err := r.podPoolStore.List()
		if err != nil {
			return nil, fmt.Errorf("failed to list pod ip pools from store: %w", err)
		}
		for _, pool := range podPoolList {
			if attrs.Selector != nil && !labelSelector.Matches(labels.Set(pool.Labels)) {
				continue
			}
			// only include pool cidrs that have been allocated to the local node.
			if cidrs, ok := localPools[pool.Name]; ok {
				for _, cidr := range cidrs {
					if cidr.Addr().Is4() {
						prefixLen := int(pool.Spec.IPv4.MaskSize)
						v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: prefixLen, PrefixLenMax: prefixLen})
					} else {
						prefixLen := int(pool.Spec.IPv6.MaskSize)
						v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: prefixLen, PrefixLenMax: prefixLen})
					}
				}
			}
		}
	case v2alpha1api.CiliumLoadBalancerIPPoolSelectorName:
		lbPoolList, err := r.lbPoolStore.List()
		if err != nil {
			return nil, fmt.Errorf("failed to list lb ip pools from store: %w", err)
		}
		for _, pool := range lbPoolList {
			if pool.Spec.Disabled {
				continue
			}
			if attrs.Selector != nil && !labelSelector.Matches(labels.Set(pool.Labels)) {
				continue
			}
			prefixesSeen := sets.New[netip.Prefix]()
			for _, cidrBlock := range pool.Spec.Blocks {
				cidr, err := netip.ParsePrefix(string(cidrBlock.Cidr))
				if err != nil {
					return nil, fmt.Errorf("failed to parse IPAM pool CIDR %s: %w", cidrBlock.Cidr, err)
				}
				if cidr.Addr().Is4() {
					v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: maxPrefixLenIPv4, PrefixLenMax: maxPrefixLenIPv4})
				} else {
					v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: maxPrefixLenIPv6, PrefixLenMax: maxPrefixLenIPv6})
				}
				prefixesSeen.Insert(cidr)
			}
		}
	case v2alpha1api.PodCIDRSelectorName:
		if attrs.Selector != nil && !labelSelector.Matches(labels.Set(params.CiliumNode.Labels)) {
			break
		}
		for _, podCIDR := range params.CiliumNode.Spec.IPAM.PodCIDRs {
			cidr, err := netip.ParsePrefix(podCIDR)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PodCIDR %s: %w", podCIDR, err)
			}
			if cidr.Addr().Is4() {
				v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: cidr.Bits(), PrefixLenMax: cidr.Bits()})
			} else {
				v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: cidr, PrefixLenMin: cidr.Bits(), PrefixLenMax: cidr.Bits()})
			}
		}
	default:
		return nil, fmt.Errorf("invalid route policy SelectorType: %s", attrs.SelectorType)
	}

	// sort prefixes to have consistent order for DeepEqual
	sort.Slice(v4Prefixes, v4Prefixes.Less)
	sort.Slice(v6Prefixes, v6Prefixes.Less)

	// dedup + sort communities to have consistent order for DeepEqual
	var communities, largeCommunities []string
	if attrs.Communities != nil {
		communities, err = mergeAndDedupCommunities(attrs.Communities.Standard, attrs.Communities.WellKnown)
		if err != nil {
			return nil, err
		}
		largeCommunities = dedupLargeCommunities(attrs.Communities.Large)
		slices.Sort(communities)
		slices.Sort(largeCommunities)
	}

	// Due to a GoBGP limitation, we need to generate a separate statement for v4 and v6 prefixes, as families
	// can not be mixed in a single statement. Nevertheless, they can be both part of the same Policy.
	if len(v4Prefixes) > 0 {
		policy.Statements = append(policy.Statements, policyStatement(neighborAddress, v4Prefixes, attrs.LocalPreference, communities, largeCommunities))
	}
	if len(v6Prefixes) > 0 {
		policy.Statements = append(policy.Statements, policyStatement(neighborAddress, v6Prefixes, attrs.LocalPreference, communities, largeCommunities))
	}
	return policy, nil
}

// populateLocalPools returns a map of allocated multi-pool IPAM CIDRs of the local CiliumNode,
// keyed by the pool name.
func (r *RoutePolicyReconciler) populateLocalPools(localNode *v2api.CiliumNode) map[string][]netip.Prefix {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "RoutePolicyReconciler",
			},
		)
	)

	if localNode == nil {
		return nil
	}

	lp := make(map[string][]netip.Prefix)
	for _, pool := range localNode.Spec.IPAM.Pools.Allocated {
		var prefixes []netip.Prefix
		for _, cidr := range pool.CIDRs {
			if p, err := cidr.ToPrefix(); err == nil {
				prefixes = append(prefixes, *p)
			} else {
				l.Errorf("invalid ipam pool cidr %v: %v", cidr, err)
			}
		}
		lp[pool.Pool] = prefixes
	}

	return lp
}

// pathAttributesPolicyName returns a policy name derived from the provided CiliumBGPPathAttributes
// (SelectorType and Selector) and NeighborAddress
func pathAttributesPolicyName(attrs v2alpha1api.CiliumBGPPathAttributes, neighborAddress string) string {
	res := neighborAddress + "-" + attrs.SelectorType
	if attrs.Selector != nil {
		h := sha256.New()
		selectorBytes, err := attrs.Selector.Marshal()
		if err == nil {
			h.Write(selectorBytes)
		}
		res += "-" + fmt.Sprintf("%x", h.Sum(nil))
	}
	return res
}

func policyStatement(neighborAddr string, prefixes []*types.RoutePolicyPrefixMatch, localPref *int64, communities, largeCommunities []string) *types.RoutePolicyStatement {
	return &types.RoutePolicyStatement{
		Conditions: types.RoutePolicyConditions{
			MatchNeighbors: []string{neighborAddr},
			MatchPrefixes:  prefixes,
		},
		Actions: types.RoutePolicyActions{
			RouteAction:         types.RoutePolicyActionNone, // continue with the processing of the next statements / policies
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

// mergeAndDedupCommunities merges numeric standard community and well-known community strings,
// deduplicated by their actual community values.
func mergeAndDedupCommunities(standard []v2alpha1api.BGPStandardCommunity, wellKnown []v2alpha1api.BGPWellKnownCommunity) ([]string, error) {
	var res []string
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
func dedupLargeCommunities(communities []v2alpha1api.BGPLargeCommunity) []string {
	var res []string
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
