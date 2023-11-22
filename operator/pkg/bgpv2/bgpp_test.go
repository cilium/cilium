// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

var (
	testBGPPPName = "01-bgpp"
	testBGPPPASN  = ptr.To[int64](65001)

	peeringPolicy = &cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		LocalASN: *testBGPPPASN,
		Neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
			{
				PeerAddress:             "10.0.0.2/32",
				PeerPort:                ptr.To[int32](1790),
				PeerASN:                 65002,
				EBGPMultihopTTL:         ptr.To[int32](255),
				ConnectRetryTimeSeconds: ptr.To[int32](5),
				HoldTimeSeconds:         ptr.To[int32](12),
				KeepAliveTimeSeconds:    ptr.To[int32](4),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To[int32](120),
				},
				AuthSecretRef: ptr.To[string]("passRef"),
				Families: []cilium_api_v2alpha1.CiliumBGPFamily{
					{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					{
						Afi:  "ipv6",
						Safi: "unicast",
					},
				},
			},
		},
	}

	peeringPolicyv6 = &cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		LocalASN: *testBGPPPASN,
		Neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
			{
				PeerAddress:             "abcd::1/128",
				PeerPort:                ptr.To[int32](1790),
				PeerASN:                 65002,
				EBGPMultihopTTL:         ptr.To[int32](255),
				ConnectRetryTimeSeconds: ptr.To[int32](5),
				HoldTimeSeconds:         ptr.To[int32](12),
				KeepAliveTimeSeconds:    ptr.To[int32](4),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To[int32](120),
				},
				AuthSecretRef: ptr.To[string]("passRef"),
				Families: []cilium_api_v2alpha1.CiliumBGPFamily{
					{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					{
						Afi:  "ipv6",
						Safi: "unicast",
					},
				},
			},
		},
	}

	peeringPolicyMultiNeigh = &cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		LocalASN: *testBGPPPASN,
		Neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
			{
				PeerAddress:             "10.0.0.2/32",
				PeerPort:                ptr.To[int32](1790),
				PeerASN:                 65002,
				EBGPMultihopTTL:         ptr.To[int32](255),
				ConnectRetryTimeSeconds: ptr.To[int32](5),
				HoldTimeSeconds:         ptr.To[int32](12),
				KeepAliveTimeSeconds:    ptr.To[int32](4),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To[int32](120),
				},
				AuthSecretRef: ptr.To[string]("passRef"),
				Families: []cilium_api_v2alpha1.CiliumBGPFamily{
					{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					{
						Afi:  "ipv6",
						Safi: "unicast",
					},
				},
			},
			{
				PeerAddress:             "10.0.0.3/32",
				PeerPort:                ptr.To[int32](1790),
				PeerASN:                 65002,
				EBGPMultihopTTL:         ptr.To[int32](255),
				ConnectRetryTimeSeconds: ptr.To[int32](5),
				HoldTimeSeconds:         ptr.To[int32](12),
				KeepAliveTimeSeconds:    ptr.To[int32](4),
				GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To[int32](120),
				},
				AuthSecretRef: ptr.To[string]("passRef"),
				Families: []cilium_api_v2alpha1.CiliumBGPFamily{
					{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					{
						Afi:  "ipv6",
						Safi: "unicast",
					},
				},
			},
		},
	}

	nodeInstance = cilium_api_v2alpha1.CiliumBGPNodeInstance{
		Name:     instanceKeyFromBGPP(testBGPPPName, *testBGPPPASN),
		LocalASN: testBGPPPASN,
		Peers: []cilium_api_v2alpha1.CiliumBGPNodePeer{
			{
				Name:        peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "10.0.0.2/32"),
				PeerAddress: ptr.To[string]("10.0.0.2"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &cilium_api_v2alpha1.PeerConfigReference{
					Group: cilium_api_v2alpha1.CustomResourceDefinitionGroup,
					Kind:  cilium_api_v2alpha1.BGPPCKindDefinition,
					Name:  peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "10.0.0.2/32"),
				},
			},
		},
	}

	nodeInstancev6 = cilium_api_v2alpha1.CiliumBGPNodeInstance{
		Name:     instanceKeyFromBGPP(testBGPPPName, *testBGPPPASN),
		LocalASN: testBGPPPASN,
		Peers: []cilium_api_v2alpha1.CiliumBGPNodePeer{
			{
				Name:        peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "abcd::1/128"),
				PeerAddress: ptr.To[string]("abcd::1"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &cilium_api_v2alpha1.PeerConfigReference{
					Group: cilium_api_v2alpha1.CustomResourceDefinitionGroup,
					Kind:  cilium_api_v2alpha1.BGPPCKindDefinition,
					Name:  peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "abcd::1/128"),
				},
			},
		},
	}

	nodeInstanceWithMultiplePeers = cilium_api_v2alpha1.CiliumBGPNodeInstance{
		Name:     instanceKeyFromBGPP(testBGPPPName, *testBGPPPASN),
		LocalASN: testBGPPPASN,
		Peers: []cilium_api_v2alpha1.CiliumBGPNodePeer{
			{
				Name:        peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "10.0.0.2/32"),
				PeerAddress: ptr.To[string]("10.0.0.2"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &cilium_api_v2alpha1.PeerConfigReference{
					Group: cilium_api_v2alpha1.CustomResourceDefinitionGroup,
					Kind:  cilium_api_v2alpha1.BGPPCKindDefinition,
					Name:  peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "10.0.0.2/32"),
				},
			},
			{
				Name:        peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "10.0.0.3/32"),
				PeerAddress: ptr.To[string]("10.0.0.3"),
				PeerASN:     ptr.To[int64](65002),
				PeerConfigRef: &cilium_api_v2alpha1.PeerConfigReference{
					Group: cilium_api_v2alpha1.CustomResourceDefinitionGroup,
					Kind:  cilium_api_v2alpha1.BGPPCKindDefinition,
					Name:  peerKeyFromBGPP(testBGPPPName, *testBGPPPASN, "10.0.0.3/32"),
				},
			},
		},
	}

	expectedPeerConfig1 = cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{
		Transport: &cilium_api_v2alpha1.CiliumBGPTransport{
			PeerPort: ptr.To[int32](1790),
		},
		Timers: &cilium_api_v2alpha1.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](5),
			HoldTimeSeconds:         ptr.To[int32](12),
			KeepAliveTimeSeconds:    ptr.To[int32](4),
		},
		GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](120),
		},
		EBGPMultihop:  ptr.To[int32](255),
		AuthSecretRef: ptr.To[string]("passRef"),
		Families: []cilium_api_v2alpha1.CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: cilium_api_v2alpha1.CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Advertisements: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.2-32",
					},
				},
			},
			{
				CiliumBGPFamily: cilium_api_v2alpha1.CiliumBGPFamily{
					Afi:  "ipv6",
					Safi: "unicast",
				},
				Advertisements: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.2-32",
					},
				},
			},
		},
	}

	expectedPeerConfigv6 = cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{
		Transport: &cilium_api_v2alpha1.CiliumBGPTransport{
			PeerPort: ptr.To[int32](1790),
		},
		Timers: &cilium_api_v2alpha1.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](5),
			HoldTimeSeconds:         ptr.To[int32](12),
			KeepAliveTimeSeconds:    ptr.To[int32](4),
		},
		GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](120),
		},
		EBGPMultihop:  ptr.To[int32](255),
		AuthSecretRef: ptr.To[string]("passRef"),
		Families: []cilium_api_v2alpha1.CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: cilium_api_v2alpha1.CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Advertisements: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						bgpPPAdvertisementLabel: "01-bgpp-65001-abcd..1-128",
					},
				},
			},
			{
				CiliumBGPFamily: cilium_api_v2alpha1.CiliumBGPFamily{
					Afi:  "ipv6",
					Safi: "unicast",
				},
				Advertisements: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						bgpPPAdvertisementLabel: "01-bgpp-65001-abcd..1-128",
					},
				},
			},
		},
	}

	expectedPeerConfig2 = cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{
		Transport: &cilium_api_v2alpha1.CiliumBGPTransport{
			PeerPort: ptr.To[int32](1790),
		},
		Timers: &cilium_api_v2alpha1.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](5),
			HoldTimeSeconds:         ptr.To[int32](12),
			KeepAliveTimeSeconds:    ptr.To[int32](4),
		},
		GracefulRestart: &cilium_api_v2alpha1.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](120),
		},
		EBGPMultihop:  ptr.To[int32](255),
		AuthSecretRef: ptr.To[string]("passRef"),
		Families: []cilium_api_v2alpha1.CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: cilium_api_v2alpha1.CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Advertisements: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.3-32",
					},
				},
			},
			{
				CiliumBGPFamily: cilium_api_v2alpha1.CiliumBGPFamily{
					Afi:  "ipv6",
					Safi: "unicast",
				},
				Advertisements: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.3-32",
					},
				},
			},
		},
	}

	peeringPolicyMultiNeighDefault = func() *cilium_api_v2alpha1.CiliumBGPVirtualRouter {
		return peeringPolicyMultiNeigh.DeepCopy()
	}

	peeringPolicyWithPodCIDR = func() *cilium_api_v2alpha1.CiliumBGPVirtualRouter {
		p := peeringPolicy.DeepCopy()
		p.ExportPodCIDR = ptr.To[bool](true)
		return p
	}

	peeringPolicyv6WithPodCIDR = func() *cilium_api_v2alpha1.CiliumBGPVirtualRouter {
		p := peeringPolicyv6.DeepCopy()
		p.ExportPodCIDR = ptr.To[bool](true)
		return p
	}

	peeringPolicyWithPodCIDRPathAttr = func() *cilium_api_v2alpha1.CiliumBGPVirtualRouter {
		p := peeringPolicyWithPodCIDR()

		for i := range p.Neighbors {
			podCIDRPathAttr := cilium_api_v2alpha1.CiliumBGPPathAttributes{
				SelectorType: cilium_api_v2alpha1.PodCIDRSelectorName,
				Selector:     nil,
				Communities: &cilium_api_v2alpha1.BGPCommunities{
					Standard: []cilium_api_v2alpha1.BGPStandardCommunity{
						"65001:1",
					},
				},
				LocalPreference: ptr.To[int64](100),
			}
			p.Neighbors[i].AdvertisedPathAttributes = append(p.Neighbors[i].AdvertisedPathAttributes, podCIDRPathAttr)
		}
		return p
	}

	peeringPolicyWithServiceCIDR = func() *cilium_api_v2alpha1.CiliumBGPVirtualRouter {
		p := peeringPolicy.DeepCopy()
		p.ServiceSelector = &slim_meta_v1.LabelSelector{
			MatchExpressions: []slim_meta_v1.LabelSelectorRequirement{
				{
					Key:      "knock-knock",
					Operator: slim_meta_v1.LabelSelectorOpIn,
					Values:   []string{"not-here"},
				},
			},
		}
		return p
	}

	peeringPolicyWithServiceCIDRPathAttr = func() *cilium_api_v2alpha1.CiliumBGPVirtualRouter {
		p := peeringPolicyWithServiceCIDR()

		for i := range p.Neighbors {
			podCIDRPathAttr := cilium_api_v2alpha1.CiliumBGPPathAttributes{
				SelectorType: cilium_api_v2alpha1.CiliumLoadBalancerIPPoolSelectorName,
				Selector:     nil,
				Communities: &cilium_api_v2alpha1.BGPCommunities{
					Standard: []cilium_api_v2alpha1.BGPStandardCommunity{
						"65001:2",
					},
				},
				LocalPreference: ptr.To[int64](200),
			}
			p.Neighbors[i].AdvertisedPathAttributes = append(p.Neighbors[i].AdvertisedPathAttributes, podCIDRPathAttr)
		}
		return p
	}
)

func Test_BGPPTranslations(t *testing.T) {
	req := require.New(t)

	tests := []struct {
		description            string
		nodes                  []*cilium_api_v2.CiliumNode
		bgpp                   *cilium_api_v2alpha1.CiliumBGPPeeringPolicy
		expectedPeerConfigs    []cilium_api_v2alpha1.CiliumBGPPeerConfig
		expectedAdvertisements []cilium_api_v2alpha1.CiliumBGPAdvertisement
		expectedNodeConfigs    []cilium_api_v2alpha1.CiliumBGPNodeConfig
	}{
		{
			description: "BGP Peering policy, with multiple neighbors",
			nodes: []*cilium_api_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			bgpp: &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "01-bgpp",
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
						*peeringPolicyMultiNeighDefault(),
					},
				},
			},
			expectedPeerConfigs: []cilium_api_v2alpha1.CiliumBGPPeerConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfig1,
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.3-32",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfig2,
				},
			},
			expectedNodeConfigs: []cilium_api_v2alpha1.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPNodeSpec{
						BGPInstances: []cilium_api_v2alpha1.CiliumBGPNodeInstance{
							nodeInstanceWithMultiplePeers,
						},
					},
				},
			},
			expectedAdvertisements: nil,
		},
		{
			description: "BGP Peering policy, pod cidr advertisement",
			nodes: []*cilium_api_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			bgpp: &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "01-bgpp",
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
						*peeringPolicyWithPodCIDR(),
					},
				},
			},
			expectedPeerConfigs: []cilium_api_v2alpha1.CiliumBGPPeerConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfig1,
				},
			},
			expectedNodeConfigs: []cilium_api_v2alpha1.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPNodeSpec{
						BGPInstances: []cilium_api_v2alpha1.CiliumBGPNodeInstance{
							nodeInstance,
						},
					},
				},
			},
			expectedAdvertisements: []cilium_api_v2alpha1.CiliumBGPAdvertisement{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						Labels: map[string]string{
							bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.2-32",
						},
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPAdvertisementSpec{
						Advertisements: []cilium_api_v2alpha1.Advertisement{
							{
								AdvertisementType: cilium_api_v2alpha1.PodCIDRAdvert,
								Selector:          nil,
								Attributes:        nil,
							},
						},
					},
				},
			},
		},
		{
			description: "BGP Peering policy, pod cidr advertisement and BGP attributes",
			nodes: []*cilium_api_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			bgpp: &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "01-bgpp",
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
						*peeringPolicyWithPodCIDRPathAttr(),
					},
				},
			},
			expectedPeerConfigs: []cilium_api_v2alpha1.CiliumBGPPeerConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfig1,
				},
			},
			expectedNodeConfigs: []cilium_api_v2alpha1.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPNodeSpec{
						BGPInstances: []cilium_api_v2alpha1.CiliumBGPNodeInstance{
							nodeInstance,
						},
					},
				},
			},
			expectedAdvertisements: []cilium_api_v2alpha1.CiliumBGPAdvertisement{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						Labels: map[string]string{
							bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.2-32",
						},
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPAdvertisementSpec{
						Advertisements: []cilium_api_v2alpha1.Advertisement{
							{
								AdvertisementType: cilium_api_v2alpha1.PodCIDRAdvert,
								Selector:          nil,
								Attributes: &cilium_api_v2alpha1.CiliumBGPAttributes{
									Community: &cilium_api_v2alpha1.BGPCommunities{
										Standard: []cilium_api_v2alpha1.BGPStandardCommunity{
											"65001:1",
										},
									},
									LocalPreference: ptr.To[int64](100),
								},
							},
						},
					},
				},
			},
		},
		{
			description: "BGP Peering policy, lb cidr advertisement",
			nodes: []*cilium_api_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			bgpp: &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "01-bgpp",
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
						*peeringPolicyWithServiceCIDR(),
					},
				},
			},
			expectedPeerConfigs: []cilium_api_v2alpha1.CiliumBGPPeerConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfig1,
				},
			},
			expectedNodeConfigs: []cilium_api_v2alpha1.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPNodeSpec{
						BGPInstances: []cilium_api_v2alpha1.CiliumBGPNodeInstance{
							nodeInstance,
						},
					},
				},
			},
			expectedAdvertisements: []cilium_api_v2alpha1.CiliumBGPAdvertisement{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						Labels: map[string]string{
							bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.2-32",
						},
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPAdvertisementSpec{
						Advertisements: []cilium_api_v2alpha1.Advertisement{
							{
								AdvertisementType: cilium_api_v2alpha1.CiliumLoadBalancerIPAdvert,
								Selector:          peeringPolicyWithServiceCIDR().ServiceSelector,
								Attributes:        nil,
							},
						},
					},
				},
			},
		},
		{
			description: "BGP Peering policy, lb cidr advertisement with path attributes",
			nodes: []*cilium_api_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			bgpp: &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "01-bgpp",
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
						*peeringPolicyWithServiceCIDRPathAttr(),
					},
				},
			},
			expectedPeerConfigs: []cilium_api_v2alpha1.CiliumBGPPeerConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfig1,
				},
			},
			expectedNodeConfigs: []cilium_api_v2alpha1.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPNodeSpec{
						BGPInstances: []cilium_api_v2alpha1.CiliumBGPNodeInstance{
							nodeInstance,
						},
					},
				},
			},
			expectedAdvertisements: []cilium_api_v2alpha1.CiliumBGPAdvertisement{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-10.0.0.2-32",
						Labels: map[string]string{
							bgpPPAdvertisementLabel: "01-bgpp-65001-10.0.0.2-32",
						},
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPAdvertisementSpec{
						Advertisements: []cilium_api_v2alpha1.Advertisement{
							{
								AdvertisementType: cilium_api_v2alpha1.CiliumLoadBalancerIPAdvert,
								Selector:          peeringPolicyWithServiceCIDR().ServiceSelector,
								Attributes: &cilium_api_v2alpha1.CiliumBGPAttributes{
									Community: &cilium_api_v2alpha1.BGPCommunities{
										Standard: []cilium_api_v2alpha1.BGPStandardCommunity{
											"65001:2",
										},
									},
									LocalPreference: ptr.To[int64](200),
								},
							},
						},
					},
				},
			},
		},
		{
			description: "BGP Peering policy, ipv6 with pod cidr advertisement",
			nodes: []*cilium_api_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			bgpp: &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "01-bgpp",
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
					VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
						*peeringPolicyv6WithPodCIDR(),
					},
				},
			},
			expectedPeerConfigs: []cilium_api_v2alpha1.CiliumBGPPeerConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-abcd..1-128",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: expectedPeerConfigv6,
				},
			},
			expectedNodeConfigs: []cilium_api_v2alpha1.CiliumBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPNodeSpec{
						BGPInstances: []cilium_api_v2alpha1.CiliumBGPNodeInstance{
							nodeInstancev6,
						},
					},
				},
			},
			expectedAdvertisements: []cilium_api_v2alpha1.CiliumBGPAdvertisement{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "01-bgpp-65001-abcd..1-128",
						Labels: map[string]string{
							bgpPPAdvertisementLabel: "01-bgpp-65001-abcd..1-128",
						},
						OwnerReferences: []meta_v1.OwnerReference{
							{
								Kind: cilium_api_v2alpha1.BGPPKindDefinition,
								Name: "01-bgpp",
							},
						},
					},
					Spec: cilium_api_v2alpha1.CiliumBGPAdvertisementSpec{
						Advertisements: []cilium_api_v2alpha1.Advertisement{
							{
								AdvertisementType: cilium_api_v2alpha1.PodCIDRAdvert,
								Selector:          nil,
								Attributes:        nil,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			f := newFixture()
			f.hive.Start(ctx)
			defer f.hive.Stop(ctx)

			for _, node := range test.nodes {
				upsertNode(req, ctx, f, node)
			}

			upsertBGPP(req, ctx, f, test.bgpp)

			// validate peer templates
			req.Eventually(func() bool {
				peerConfigs, err := f.bgppcClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					return false
				}
				if len(peerConfigs.Items) != len(test.expectedPeerConfigs) {
					return false
				}

				for _, expectedPeerConfig := range test.expectedPeerConfigs {
					runningPeerConfig, err := f.bgppcClient.Get(ctx, expectedPeerConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						return false
					}

					// compare owner
					if !isSameOwner(expectedPeerConfig.GetOwnerReferences(), runningPeerConfig.GetOwnerReferences()) {
						return false
					}

					if !runningPeerConfig.Spec.DeepEqual(&expectedPeerConfig.Spec) {
						return false
					}
				}
				return true
			}, TestTimeout, 50*time.Millisecond)

			// validate advertisements
			req.Eventually(func() bool {
				advertisements, err := f.bgpaClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					return false
				}

				if len(advertisements.Items) != len(test.expectedAdvertisements) {
					return false
				}

				for _, expectedAdvert := range test.expectedAdvertisements {
					runningAdvert, err := f.bgpaClient.Get(ctx, expectedAdvert.Name, meta_v1.GetOptions{})
					if err != nil {
						return false
					}

					// compare owner
					if !isSameOwner(expectedAdvert.GetOwnerReferences(), runningAdvert.GetOwnerReferences()) {
						return false
					}

					// compare labels
					if !reflect.DeepEqual(expectedAdvert.Labels, runningAdvert.Labels) {
						return false
					}

					if !runningAdvert.Spec.DeepEqual(&expectedAdvert.Spec) {
						return false
					}
				}
				return true
			}, TestTimeout, 50*time.Millisecond)

			// validate nodes
			req.Eventually(func() bool {
				nodeConfigs, err := f.bgpnClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					return false
				}

				if len(nodeConfigs.Items) != len(test.expectedNodeConfigs) {
					return false
				}

				for _, expectedNodeConfig := range test.expectedNodeConfigs {
					runningNodeConfig, err := f.bgpnClient.Get(ctx, expectedNodeConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						return false
					}

					if !isSameOwner(expectedNodeConfig.GetOwnerReferences(), runningNodeConfig.GetOwnerReferences()) {
						return false
					}

					if !runningNodeConfig.Spec.DeepEqual(&expectedNodeConfig.Spec) {
						return false
					}
				}

				return true
			}, TestTimeout, 50*time.Millisecond)
		})
	}
}

// Test_BGPPCleanup tests that resources created by BGP Peering Policy are cleaned up when the policy is deleted.
func Test_BGPPCleanup(t *testing.T) {
	// initialization
	req := require.New(t)
	f := newFixture()
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f.hive.Start(ctx)
	defer f.hive.Stop(ctx)

	// create new resource
	upsertNode(req, ctx, f, &cilium_api_v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"bgp": "rack1",
			},
		},
	})

	upsertNode(req, ctx, f, &cilium_api_v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node-2",
			Labels: map[string]string{
				"bgp": "rack1",
			},
		},
	})

	upsertBGPP(req, ctx, f, &cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "01-bgpp",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"bgp": "rack1",
				},
			},
			VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
				*peeringPolicyWithPodCIDR(),
			},
		},
	})

	// check for existence of various resources
	assert.Eventually(t, func() bool {
		nodes, err := f.bgpnClient.List(ctx, meta_v1.ListOptions{})
		assert.NoError(t, err)

		// expected 2 node configs
		if 2 != len(nodes.Items) {
			return false
		}

		adverts, err := f.bgpaClient.List(ctx, meta_v1.ListOptions{})
		assert.NoError(t, err)

		// expected 1 advertisement
		if 1 != len(adverts.Items) {
			return false
		}

		peerConfigs, err := f.bgppcClient.List(ctx, meta_v1.ListOptions{})
		assert.NoError(t, err)

		// expected 1 peer config
		return 1 == len(peerConfigs.Items)
	}, TestTimeout, time.Second)

	// delete bgp peering policy resource
	deleteBGPPP(req, ctx, f, "01-bgpp")

	assert.Eventually(t, func() bool {
		nodes, err := f.bgpnClient.List(ctx, meta_v1.ListOptions{})
		assert.NoError(t, err)

		// expected 0 node configs
		if 0 != len(nodes.Items) {
			return false
		}
		adverts, err := f.bgpaClient.List(ctx, meta_v1.ListOptions{})
		assert.NoError(t, err)

		// expected 0 advertisement
		if 0 != len(adverts.Items) {
			return false
		}

		peerConfigs, err := f.bgppcClient.List(ctx, meta_v1.ListOptions{})
		assert.NoError(t, err)

		// expected 0 peer config
		return 0 == len(peerConfigs.Items)
	}, TestTimeout, time.Second)
}

func upsertBGPP(req *require.Assertions, ctx context.Context, f *fixture, bgpp *cilium_api_v2alpha1.CiliumBGPPeeringPolicy) {
	if bgpp == nil {
		return
	}

	_, err := f.bgppClient.Get(ctx, bgpp.Name, meta_v1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		_, err = f.bgppClient.Create(ctx, bgpp, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.bgppClient.Update(ctx, bgpp, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func deleteBGPPP(req *require.Assertions, ctx context.Context, f *fixture, name string) {
	_, err := f.bgppClient.Get(ctx, name, meta_v1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		return // already deleted
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		err = f.bgppClient.Delete(ctx, name, meta_v1.DeleteOptions{})
	}
	req.NoError(err)
}
