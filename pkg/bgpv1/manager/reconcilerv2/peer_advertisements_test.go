// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	peerAdvertTestLogger = logrus.WithField("unit_test", "advertisements")
)

// test fixtures
var (
	redPodCIDRAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPPodCIDRAdvert,
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65000:100",
				},
			},
		},
	}

	redPodIPPoolAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPCiliumPodIPPoolAdvert,
		// CiliumPodIPPool selector is not set for this test
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65000:200",
				},
			},
		},
	}

	redServiceLBAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPServiceAdvert,
		Service: &v2.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{
				v2.BGPLoadBalancerIPAddr,
			},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65000:300",
				},
			},
		},
	}

	redAdvert = &v2.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{
				redPodCIDRAdvert,
				redPodIPPoolAdvert,
				redServiceLBAdvert,
			},
		},
	}

	redAdvertWithSelector = func(selector *slimv1.LabelSelector) *v2.CiliumBGPAdvertisement {
		cpy := redAdvert.DeepCopy()
		for i := range cpy.Spec.Advertisements {
			cpy.Spec.Advertisements[i].Selector = selector
		}
		return cpy
	}

	bluePodCIDRAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPPodCIDRAdvert,
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65355:100",
				},
			},
		},
	}
	bluePodIPPoolAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPCiliumPodIPPoolAdvert,
		// CiliumPodIPPool selector is not set for this test
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65355:200",
				},
			},
		},
	}
	blueServicePodAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPServiceAdvert,
		Service: &v2.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{
				v2.BGPLoadBalancerIPAddr,
			},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard: []v2.BGPStandardCommunity{
					"65355:300",
				},
			},
		},
	}

	blueAdvert = &v2.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blue-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "blue_bgp",
			},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{
				bluePodCIDRAdvert,
				bluePodIPPoolAdvert,
				blueServicePodAdvert,
			},
		},
	}

	blueAdvertWithSelector = func(selector *slimv1.LabelSelector) *v2.CiliumBGPAdvertisement {
		cpy := blueAdvert.DeepCopy()
		for i := range cpy.Spec.Advertisements {
			cpy.Spec.Advertisements[i].Selector = selector
		}
		return cpy
	}

	// red peer config
	redPeerConfig = &v2.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red",
		},
		Spec: v2.CiliumBGPPeerConfigSpec{
			Families: []v2.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "red_bgp",
						},
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "red_bgp",
						},
					},
				},
			},
		},
	}

	// red peer config - v4
	redPeerConfigV4 = &v2.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red-v4",
		},
		Spec: v2.CiliumBGPPeerConfigSpec{
			Families: []v2.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "red_bgp",
						},
					},
				},
			},
		},
	}

	// blue peer config
	bluePeerConfig = &v2.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-blue",
		},
		Spec: v2.CiliumBGPPeerConfigSpec{
			Families: []v2.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "blue_bgp",
						},
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "blue_bgp",
						},
					},
				},
			},
		},
	}

	// peer configuration
	redPeer65001 = v2.CiliumBGPNodePeer{
		Name:        "red-peer-65001",
		PeerAddress: ptr.To[string]("10.10.10.1"),
		PeerConfigRef: &v2.PeerConfigReference{
			Name: "peer-config-red",
		},
	}

	bluePeer65001 = v2.CiliumBGPNodePeer{
		Name:        "blue-peer-65001",
		PeerAddress: ptr.To[string]("10.10.10.2"),
		PeerConfigRef: &v2.PeerConfigReference{
			Name: "peer-config-blue",
		},
	}
)

func Test_GetAdvertisements(t *testing.T) {
	tests := []struct {
		name               string
		peerConfig         []*v2.CiliumBGPPeerConfig
		advertisements     []*v2.CiliumBGPAdvertisement
		reqAdvertTypes     []v2.BGPAdvertisementType
		reqBGPNodeInstance *v2.CiliumBGPNodeInstance
		expectedError      bool
		expectedAdverts    PeerAdvertisements
	}{
		{
			name:       "Peer config does not exist for peer in BGPNodeInstance",
			peerConfig: []*v2.CiliumBGPPeerConfig{},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
			},
			reqBGPNodeInstance: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes:  []v2.BGPAdvertisementType{v2.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{},
		},
		{
			name: "Expecting PodCIDR advertisement for single peer",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes: []v2.BGPAdvertisementType{v2.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert},
				},
			},
		},
		{
			name: "Expecting PodCIDR advertisement for dual peers",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red",
						},
					},
					{
						Name: "blue-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-blue",
						},
					},
				},
			},
			reqAdvertTypes: []v2.BGPAdvertisementType{v2.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert},
				},
				"blue-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {bluePodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert},
				},
			},
		},
		{
			name: "Expecting no advertisement, unknown label",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				// redAdvert, red advertisement not present for this test case
				blueAdvert,
			},
			reqBGPNodeInstance: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes: []v2.BGPAdvertisementType{v2.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: nil, // empty advertisement
					{Afi: "ipv6", Safi: "unicast"}: nil, // empty advertisement
				},
			},
		},
		{
			name: "Expecting PodCIDR and Service advertisement for single peer",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes: []v2.BGPAdvertisementType{v2.BGPPodCIDRAdvert, v2.BGPServiceAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert, redServiceLBAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert, redServiceLBAdvert},
				},
			},
		},
		{
			name: "Expecting PodCIDR and Service advertisement for dual peers",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red",
						},
					},
					{
						Name: "blue-peer-65001",
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-blue",
						},
					},
				},
			},
			reqAdvertTypes: []v2.BGPAdvertisementType{v2.BGPPodCIDRAdvert, v2.BGPServiceAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert, redServiceLBAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert, redServiceLBAdvert},
				},
				"blue-peer-65001": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {bluePodCIDRAdvert, blueServicePodAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert, blueServicePodAdvert},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			params := PeerAdvertisementIn{
				Logger:          peerAdvertTestLogger,
				PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
				AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
			}

			r := NewCiliumPeerAdvertisement(params)

			advertisements, err := r.GetConfiguredAdvertisements(tt.reqBGPNodeInstance, tt.reqAdvertTypes...)
			if tt.expectedError {
				req.Error(err)
				return
			} else {
				req.NoError(err)
			}

			req.Equal(tt.expectedAdverts, advertisements)
		})
	}
}

// Test_PeerAdvertisementsEqual tests the equality of two PeerAdvertisements
func Test_PeerAdvertisementsEqual(t *testing.T) {
	tests := []struct {
		name          string
		peerAdvert1   PeerAdvertisements
		peerAdvert2   PeerAdvertisements
		expectedEqual bool
	}{
		{
			name:          "Empty PeerAdvertisements",
			peerAdvert1:   PeerAdvertisements{},
			peerAdvert2:   PeerAdvertisements{},
			expectedEqual: true,
		},
		{
			name:          "Nil PeerAdvertisements",
			peerAdvert1:   nil,
			peerAdvert2:   PeerAdvertisements{},
			expectedEqual: true,
		},
		{
			name: "Empty FamilyAdvertisements in peers",
			peerAdvert1: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{},
			},
			peerAdvert2: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{},
			},
			expectedEqual: true,
		},
		{
			name: "Nil FamilyAdvertisements in peers",
			peerAdvert1: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{},
			},
			peerAdvert2: PeerAdvertisements{
				"peer-1": nil,
			},
			expectedEqual: true,
		},
		{
			name: "Equal FamilyAdvertisements in peers",
			peerAdvert1: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert},
				},
			},
			peerAdvert2: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert},
				},
			},
			expectedEqual: true,
		},
		{
			name: "Unequal length in FamilyAdvertisements in peers",
			peerAdvert1: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert},
				},
			},
			peerAdvert2: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
				},
			},
			expectedEqual: false,
		},
		{
			name: "Unequal value in FamilyAdvertisements in peers",
			peerAdvert1: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert},
				},
			},
			peerAdvert2: PeerAdvertisements{
				"peer-1": map[v2.CiliumBGPFamily][]v2.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert},
				},
			},
			expectedEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			equal := PeerAdvertisementsEqual(tt.peerAdvert1, tt.peerAdvert2)
			req.Equal(tt.expectedEqual, equal)
		})
	}
}
