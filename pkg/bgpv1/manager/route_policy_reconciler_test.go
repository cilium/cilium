// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/cidr"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	podCIDRPrefix = netip.MustParsePrefix("10.0.0.0/24")
	podCIDR       = cidr.MustParseCIDR(podCIDRPrefix.String())

	lbPool = &v2alpha1api.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"label1": "value1",
			},
		},
		Spec: v2alpha1api.CiliumLoadBalancerIPPoolSpec{
			Cidrs: []v2alpha1api.CiliumLoadBalancerIPPoolIPBlock{
				{
					Cidr: "192.168.0.0/24",
				},
			},
		},
	}
	lbPoolUpdated = &v2alpha1api.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"label1": "value1",
			},
		},
		Spec: v2alpha1api.CiliumLoadBalancerIPPoolSpec{
			Cidrs: []v2alpha1api.CiliumLoadBalancerIPPoolIPBlock{
				{
					Cidr: "10.100.99.0/24", // UPDATED
				},
			},
		},
	}

	peerAddress = "172.16.0.1/32"

	standardCommunity = "64125:100"

	largeCommunity = "64125:4294967295:100"

	attrSelectPool = v2alpha1api.CiliumBGPPathAttributes{
		SelectorType: v2alpha1api.CiliumLoadBalancerIPPoolSelectorName,
		Selector: &slimv1.LabelSelector{
			MatchLabels: map[string]slimv1.MatchLabelsValue{
				"label1": "value1",
			},
		},
		Communities: &v2alpha1api.BGPCommunities{
			Standard: []v2alpha1api.BGPStandardCommunity{v2alpha1api.BGPStandardCommunity(standardCommunity)},
			Large:    []v2alpha1api.BGPLargeCommunity{v2alpha1api.BGPLargeCommunity(largeCommunity)},
		},
	}

	attrSelectAnyNode = v2alpha1api.CiliumBGPPathAttributes{
		SelectorType:    v2alpha1api.PodCIDRSelectorName,
		LocalPreference: pointer.Int64(150),
	}

	attrSelectNonExistingNode = v2alpha1api.CiliumBGPPathAttributes{
		SelectorType: v2alpha1api.PodCIDRSelectorName,
		Selector: &slimv1.LabelSelector{
			MatchLabels: map[string]slimv1.MatchLabelsValue{
				"node": "non-existing",
			},
		},
		LocalPreference: pointer.Int64(150),
	}

	attrSelectInvalid = v2alpha1api.CiliumBGPPathAttributes{
		SelectorType: "INVALID",
		Selector: &slimv1.LabelSelector{
			MatchLabels: map[string]slimv1.MatchLabelsValue{
				"env": "dev",
			},
		},
	}
)

type routePolicyTestInputs struct {
	podCIDRs         []*cidr.CIDR
	LBPools          []*v2alpha1api.CiliumLoadBalancerIPPool
	neighbors        []v2alpha1api.CiliumBGPNeighbor
	expectedPolicies []*types.RoutePolicy
}

func TestRoutePolicyReconciler(t *testing.T) {
	var table = []struct {
		name        string
		initial     *routePolicyTestInputs
		updated     *routePolicyTestInputs
		expectError bool
	}{
		{
			name: "add complex policy (pod CIDR + LB pool)",
			initial: &routePolicyTestInputs{
				podCIDRs: []*cidr.CIDR{
					podCIDR,
				},
				LBPools: []*v2alpha1api.CiliumLoadBalancerIPPool{
					lbPool,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectPool,
							attrSelectAnyNode,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectPool, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(lbPool.Spec.Cidrs[0].Cidr)),
											PrefixLenMin: maxPrefixLenIPv4,
											PrefixLenMax: maxPrefixLenIPv4,
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
						},
					},
					{
						Name: pathAttributesPolicyName(attrSelectAnyNode, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         podCIDRPrefix,
											PrefixLenMin: podCIDRPrefix.Bits(),
											PrefixLenMax: podCIDRPrefix.Bits(),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:        types.RoutePolicyActionNone,
									SetLocalPreference: attrSelectAnyNode.LocalPreference,
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "update policy - lb pool change",
			initial: &routePolicyTestInputs{
				LBPools: []*v2alpha1api.CiliumLoadBalancerIPPool{
					lbPool,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectPool,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectPool, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(lbPool.Spec.Cidrs[0].Cidr)),
											PrefixLenMin: maxPrefixLenIPv4,
											PrefixLenMax: maxPrefixLenIPv4,
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
						},
					},
				},
			},
			updated: &routePolicyTestInputs{
				LBPools: []*v2alpha1api.CiliumLoadBalancerIPPool{
					lbPoolUpdated, // UPDATED - modified CIDR
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectPool,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectPool, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(lbPoolUpdated.Spec.Cidrs[0].Cidr)),
											PrefixLenMin: maxPrefixLenIPv4,
											PrefixLenMax: maxPrefixLenIPv4,
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "delete policy - non-matching selector",
			initial: &routePolicyTestInputs{
				podCIDRs: []*cidr.CIDR{
					podCIDR,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectAnyNode,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectAnyNode, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         podCIDRPrefix,
											PrefixLenMin: podCIDRPrefix.Bits(),
											PrefixLenMax: podCIDRPrefix.Bits(),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:        types.RoutePolicyActionNone,
									SetLocalPreference: attrSelectAnyNode.LocalPreference,
								},
							},
						},
					},
				},
			},
			updated: &routePolicyTestInputs{
				podCIDRs: []*cidr.CIDR{
					podCIDR,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectNonExistingNode, // UPDATED - not matching the node
						},
					},
				},
				expectedPolicies: nil,
			},
			expectError: false,
		},
		{
			name: "error - invalid selector",
			initial: &routePolicyTestInputs{
				podCIDRs: []*cidr.CIDR{
					podCIDR,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectInvalid,
						},
					},
				},
				expectedPolicies: nil,
			},
			expectError: true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			require.NoError(t, err)

			testSC.Config = &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: pointer.Bool(true),
				Neighbors:     tt.initial.neighbors,
			}

			store := newMockBGPCPResourceStore[*v2alpha1api.CiliumLoadBalancerIPPool]()
			for _, obj := range tt.initial.LBPools {
				store.Upsert(obj)
			}

			policyReconciler := NewRoutePolicyReconciler(store).Reconciler.(*RoutePolicyReconciler)
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: testSC.Config,
				Node: &node.LocalNode{
					Node: nodeTypes.Node{
						IPv4SecondaryAllocCIDRs: tt.initial.podCIDRs,
					},
				},
			}

			// initial reconcile
			err = policyReconciler.Reconcile(context.Background(), params)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// validate cached vs. expected policies
			validatePoliciesMatch(t, policyReconciler.getMetadata(testSC), tt.initial.expectedPolicies)

			if tt.updated == nil {
				return // not testing update / remove
			}

			// follow-up reconcile - update:
			params.DesiredConfig.Neighbors = tt.updated.neighbors
			params.Node.Node.IPv4SecondaryAllocCIDRs = tt.updated.podCIDRs
			for _, obj := range tt.updated.LBPools {
				store.Upsert(obj)
			}
			err = policyReconciler.Reconcile(context.Background(), params)
			require.NoError(t, err)

			// validate cached vs. expected policies
			validatePoliciesMatch(t, policyReconciler.getMetadata(testSC), tt.updated.expectedPolicies)
		})
	}
}

func validatePoliciesMatch(t *testing.T, actual map[string]*types.RoutePolicy, expected []*types.RoutePolicy) {
	require.Len(t, actual, len(expected))

	for _, expPolicy := range expected {
		policy := actual[expPolicy.Name]
		require.NotNil(t, policy)
		require.EqualValues(t, policy, expPolicy)
	}
}
