// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	podCIDR       = "10.0.0.0/24"
	podCIDRPrefix = netip.MustParsePrefix(podCIDR)

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

	podPool = &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				"label1": "value1",
			}},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4: &v2alpha1api.IPv4PoolSpec{
				CIDRs:    []v2alpha1api.PoolCIDR{"100.0.0.0/16"},
				MaskSize: 24,
			},
			IPv6: &v2alpha1api.IPv6PoolSpec{
				CIDRs:    []v2alpha1api.PoolCIDR{"2001:0:0:1234::/64"},
				MaskSize: 96,
			},
		},
	}

	podPoolUpdated = &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"label1": "value1",
			}},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4: &v2alpha1api.IPv4PoolSpec{
				CIDRs:    []v2alpha1api.PoolCIDR{"100.0.0.0/16", "100.1.0.0/16"},
				MaskSize: 24,
			},
			IPv6: &v2alpha1api.IPv6PoolSpec{
				CIDRs:    []v2alpha1api.PoolCIDR{"2001:0:0:1234::/64", "2002:0:0:1234::/64"},
				MaskSize: 96,
			},
		},
	}

	nodePool = ipamTypes.IPAMPoolAllocation{
		Pool: podPool.Name,
		CIDRs: []ipamTypes.IPAMPodCIDR{
			"100.0.0.0/16",
			"2001:0:0:1234::/64",
		},
	}

	nodePoolUpdated = ipamTypes.IPAMPoolAllocation{
		Pool: podPool.Name,
		CIDRs: []ipamTypes.IPAMPodCIDR{
			"100.0.0.0/16",
			"100.1.0.0/16",
			"2001:0:0:1234::/64",
			"2002:0:0:1234::/64",
		},
	}

	peerAddress = "172.16.0.1/32"

	standardCommunity  = "64125:100"
	wellKnownCommunity = "no-advertise"
	largeCommunity     = "64125:4294967295:100"

	attrSelectLBPool = v2alpha1api.CiliumBGPPathAttributes{
		SelectorType: v2alpha1api.CiliumLoadBalancerIPPoolSelectorName,
		Selector: &slimv1.LabelSelector{
			MatchLabels: map[string]slimv1.MatchLabelsValue{
				"label1": "value1",
			},
		},
		Communities: &v2alpha1api.BGPCommunities{
			Standard:  []v2alpha1api.BGPStandardCommunity{v2alpha1api.BGPStandardCommunity(standardCommunity)},
			WellKnown: []v2alpha1api.BGPWellKnownCommunity{v2alpha1api.BGPWellKnownCommunity(wellKnownCommunity)},
			Large:     []v2alpha1api.BGPLargeCommunity{v2alpha1api.BGPLargeCommunity(largeCommunity)},
		},
	}

	attrSelectPodPool = v2alpha1api.CiliumBGPPathAttributes{
		SelectorType: v2alpha1api.CiliumPodIPPoolSelectorName,
		Selector: &slimv1.LabelSelector{
			MatchLabels: map[string]slimv1.MatchLabelsValue{
				"label1": "value1",
			},
		},
		Communities: &v2alpha1api.BGPCommunities{
			Standard:  []v2alpha1api.BGPStandardCommunity{v2alpha1api.BGPStandardCommunity(standardCommunity)},
			WellKnown: []v2alpha1api.BGPWellKnownCommunity{v2alpha1api.BGPWellKnownCommunity(wellKnownCommunity)},
			Large:     []v2alpha1api.BGPLargeCommunity{v2alpha1api.BGPLargeCommunity(largeCommunity)},
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
	podCIDRs         []string
	LBPools          []*v2alpha1api.CiliumLoadBalancerIPPool
	NodePools        []ipamTypes.IPAMPoolAllocation
	PodPools         []*v2alpha1api.CiliumPodIPPool
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
			name: "add complex policy (pod CIDR + LB pool + Pod pool)",
			initial: &routePolicyTestInputs{
				podCIDRs: []string{
					podCIDR,
				},
				LBPools: []*v2alpha1api.CiliumLoadBalancerIPPool{
					lbPool,
				},
				PodPools: []*v2alpha1api.CiliumPodIPPool{
					podPool,
				},
				NodePools: []ipamTypes.IPAMPoolAllocation{
					nodePool,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectLBPool,
							attrSelectPodPool,
							attrSelectAnyNode,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectLBPool, peerAddress),
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
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
						},
					},
					{
						Name: pathAttributesPolicyName(attrSelectPodPool, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(podPool.Spec.IPv4.CIDRs[0])),
											PrefixLenMin: int(podPool.Spec.IPv4.MaskSize),
											PrefixLenMax: int(podPool.Spec.IPv4.MaskSize),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(podPool.Spec.IPv6.CIDRs[0])),
											PrefixLenMin: int(podPool.Spec.IPv6.MaskSize),
											PrefixLenMax: int(podPool.Spec.IPv6.MaskSize),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
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
							attrSelectLBPool,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectLBPool, peerAddress),
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
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
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
							attrSelectLBPool,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectLBPool, peerAddress),
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
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
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
			name: "update policy - pod pool change",
			initial: &routePolicyTestInputs{
				PodPools: []*v2alpha1api.CiliumPodIPPool{
					podPool,
				},
				NodePools: []ipamTypes.IPAMPoolAllocation{
					nodePool,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectPodPool,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectPodPool, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(podPool.Spec.IPv4.CIDRs[0])),
											PrefixLenMin: int(podPool.Spec.IPv4.MaskSize),
											PrefixLenMax: int(podPool.Spec.IPv4.MaskSize),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(podPool.Spec.IPv6.CIDRs[0])),
											PrefixLenMin: int(podPool.Spec.IPv6.MaskSize),
											PrefixLenMax: int(podPool.Spec.IPv6.MaskSize),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
						},
					},
				},
			},
			updated: &routePolicyTestInputs{
				PodPools: []*v2alpha1api.CiliumPodIPPool{
					podPoolUpdated,
				},
				NodePools: []ipamTypes.IPAMPoolAllocation{
					nodePoolUpdated,
				},
				neighbors: []v2alpha1api.CiliumBGPNeighbor{
					{
						PeerAddress: peerAddress,
						AdvertisedPathAttributes: []v2alpha1api.CiliumBGPPathAttributes{
							attrSelectPodPool,
						},
					},
				},
				expectedPolicies: []*types.RoutePolicy{
					{
						Name: pathAttributesPolicyName(attrSelectPodPool, peerAddress),
						Type: types.RoutePolicyTypeExport,
						Statements: []*types.RoutePolicyStatement{
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(podPoolUpdated.Spec.IPv4.CIDRs[0])),
											PrefixLenMin: int(podPoolUpdated.Spec.IPv4.MaskSize),
											PrefixLenMax: int(podPoolUpdated.Spec.IPv4.MaskSize),
										},
										{
											CIDR:         netip.MustParsePrefix(string(podPoolUpdated.Spec.IPv4.CIDRs[1])),
											PrefixLenMin: int(podPoolUpdated.Spec.IPv4.MaskSize),
											PrefixLenMax: int(podPoolUpdated.Spec.IPv4.MaskSize),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
									AddLargeCommunities: []string{largeCommunity},
								},
							},
							{
								Conditions: types.RoutePolicyConditions{
									MatchNeighbors: []string{peerAddress},
									MatchPrefixes: []*types.RoutePolicyPrefixMatch{
										{
											CIDR:         netip.MustParsePrefix(string(podPoolUpdated.Spec.IPv6.CIDRs[0])),
											PrefixLenMin: int(podPoolUpdated.Spec.IPv6.MaskSize),
											PrefixLenMax: int(podPoolUpdated.Spec.IPv6.MaskSize),
										},
										{
											CIDR:         netip.MustParsePrefix(string(podPoolUpdated.Spec.IPv6.CIDRs[1])),
											PrefixLenMin: int(podPoolUpdated.Spec.IPv6.MaskSize),
											PrefixLenMax: int(podPoolUpdated.Spec.IPv6.MaskSize),
										},
									},
								},
								Actions: types.RoutePolicyActions{
									RouteAction:         types.RoutePolicyActionNone,
									AddCommunities:      []string{standardCommunity, wellKnownCommunity},
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
				podCIDRs: []string{
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
				podCIDRs: []string{
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
				podCIDRs: []string{
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
			testSC, err := instance.NewServerWithConfig(context.Background(), log, srvParams)
			require.NoError(t, err)

			testSC.Config = &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: pointer.Bool(true),
				Neighbors:     tt.initial.neighbors,
			}

			lbStore := store.NewMockBGPCPResourceStore[*v2alpha1api.CiliumLoadBalancerIPPool]()
			for _, obj := range tt.initial.LBPools {
				lbStore.Upsert(obj)
			}

			podStore := store.NewMockBGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]()
			for _, obj := range tt.initial.PodPools {
				podStore.Upsert(obj)
			}

			policyReconciler := NewRoutePolicyReconciler(lbStore, podStore).Reconciler.(*RoutePolicyReconciler)
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: testSC.Config,
				CiliumNode: &v2.CiliumNode{
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: tt.initial.podCIDRs,
							Pools: ipamTypes.IPAMPoolSpec{
								Allocated: tt.initial.NodePools,
							},
						},
					},
				},
			}

			// Run the reconciler twice to ensure idempotency. This
			// simulates the retrying behavior of the controller.
			for i := 0; i < 2; i++ {
				t.Run(tt.name+"-init", func(t *testing.T) {
					err = policyReconciler.Reconcile(context.Background(), params)
					if tt.expectError {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
				})
			}

			// validate cached vs. expected policies
			validatePoliciesMatch(t, policyReconciler.getMetadata(testSC), tt.initial.expectedPolicies)

			if tt.updated == nil {
				return // not testing update / remove
			}

			// follow-up reconcile - update:
			params.DesiredConfig.Neighbors = tt.updated.neighbors
			params.CiliumNode.Spec.IPAM.Pools.Allocated = tt.updated.NodePools
			params.CiliumNode.Spec.IPAM.PodCIDRs = tt.updated.podCIDRs
			for _, obj := range tt.updated.LBPools {
				lbStore.Upsert(obj)
			}
			for _, obj := range tt.updated.PodPools {
				podStore.Upsert(obj)
			}
			// Run the reconciler twice to ensure idempotency. This
			// simulates the retrying behavior of the controller.
			for i := 0; i < 2; i++ {
				t.Run(tt.name+"-follow-up", func(t *testing.T) {
					err = policyReconciler.Reconcile(context.Background(), params)
					require.NoError(t, err)
				})
			}

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

func TestCommunityDeduplication(t *testing.T) {
	var table = []struct {
		name      string
		standard  []v2alpha1api.BGPStandardCommunity
		wellKnown []v2alpha1api.BGPWellKnownCommunity
		large     []v2alpha1api.BGPLargeCommunity
		expected  []string
		expectErr bool
	}{
		{
			name:     "single standard",
			standard: []v2alpha1api.BGPStandardCommunity{"64125:100"},
			expected: []string{"64125:100"},
		},
		{
			name:      "single well-known",
			wellKnown: []v2alpha1api.BGPWellKnownCommunity{"no-advertise"},
			expected:  []string{"no-advertise"},
		},
		{
			name:     "single large",
			large:    []v2alpha1api.BGPLargeCommunity{"64125:4294967295:100"},
			expected: []string{"64125:4294967295:100"},
		},
		{
			name:     "duplicate standard",
			standard: []v2alpha1api.BGPStandardCommunity{"0:100", "100", "0:101", "0:100"},
			expected: []string{"0:100", "0:101"},
		},
		{
			name:      "duplicate well-known",
			wellKnown: []v2alpha1api.BGPWellKnownCommunity{"no-export", "no-advertise", "no-export"},
			expected:  []string{"no-export", "no-advertise"},
		},
		{
			name:      "invalid standard",
			standard:  []v2alpha1api.BGPStandardCommunity{"64125:100", "999999:999999", "64125:101"},
			expectErr: true,
		},
		{
			name:      "invalid well-known",
			wellKnown: []v2alpha1api.BGPWellKnownCommunity{"no-export", "NON-EXISTING"},
			expectErr: true,
		},
		{
			name:     "duplicate large",
			large:    []v2alpha1api.BGPLargeCommunity{"64125:4294967295:100", "64125:4294967295:200", "64125:4294967295:200"},
			expected: []string{"64125:4294967295:100", "64125:4294967295:200"},
		},
		{
			name:      "standard + well-known duplicated",
			standard:  []v2alpha1api.BGPStandardCommunity{"64125:100", "64125:101", "65535:65282"},
			wellKnown: []v2alpha1api.BGPWellKnownCommunity{"no-export", "no-advertise"}, // no-advertise = "65535:65282"
			expected:  []string{"64125:100", "64125:101", "65535:65282", "no-export"},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			res, err := mergeAndDedupCommunities(tt.standard, tt.wellKnown)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			res2 := dedupLargeCommunities(tt.large)

			require.EqualValues(t, tt.expected, append(res, res2...))
		})
	}
}
