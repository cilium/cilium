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
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	peerAdvertTestLogger = logrus.WithField("unit_test", "advertisements")
)

// test fixtures
var (
	redPodCIDRAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPPodCIDRAdvert,
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard: []v2alpha1.BGPStandardCommunity{
					"65000:100",
				},
			},
		},
	}

	redPodIPPoolAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPCiliumPodIPPoolAdvert,
		// CiliumPodIPPool selector is not set for this test
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard: []v2alpha1.BGPStandardCommunity{
					"65000:200",
				},
			},
		},
	}

	redServicePodAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPServiceAdvert,
		Service: &v2alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{
				v2alpha1.BGPLoadBalancerIPAddr,
			},
		},
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard: []v2alpha1.BGPStandardCommunity{
					"65000:300",
				},
			},
		},
	}

	redAdvert = &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				redPodCIDRAdvert,
				redPodIPPoolAdvert,
				redServicePodAdvert,
			},
		},
	}

	redAdvertWithSelector = func(selector *slimv1.LabelSelector) *v2alpha1.CiliumBGPAdvertisement {
		cpy := redAdvert.DeepCopy()
		for i := range cpy.Spec.Advertisements {
			cpy.Spec.Advertisements[i].Selector = selector
		}
		return cpy
	}

	bluePodCIDRAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPPodCIDRAdvert,
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard: []v2alpha1.BGPStandardCommunity{
					"65555:100",
				},
			},
		},
	}
	bluePodIPPoolAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPCiliumPodIPPoolAdvert,
		// CiliumPodIPPool selector is not set for this test
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard: []v2alpha1.BGPStandardCommunity{
					"65555:200",
				},
			},
		},
	}
	blueServicePodAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPServiceAdvert,
		Service: &v2alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{
				v2alpha1.BGPLoadBalancerIPAddr,
			},
		},
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard: []v2alpha1.BGPStandardCommunity{
					"65555:300",
				},
			},
		},
	}

	blueAdvert = &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blue-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "blue_bgp",
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				bluePodCIDRAdvert,
				bluePodIPPoolAdvert,
				blueServicePodAdvert,
			},
		},
	}

	blueAdvertWithSelector = func(selector *slimv1.LabelSelector) *v2alpha1.CiliumBGPAdvertisement {
		cpy := blueAdvert.DeepCopy()
		for i := range cpy.Spec.Advertisements {
			cpy.Spec.Advertisements[i].Selector = selector
		}
		return cpy
	}

	// red peer config
	redPeerConfig = &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red",
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
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
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
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
	redPeerConfigV4 = &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red-v4",
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
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
	bluePeerConfig = &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-blue",
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
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
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
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
)

func Test_GetAdvertisements(t *testing.T) {
	tests := []struct {
		name               string
		peerConfig         []*v2alpha1.CiliumBGPPeerConfig
		advertisements     []*v2alpha1.CiliumBGPAdvertisement
		reqAdvertTypes     []v2alpha1.BGPAdvertisementType
		reqBGPNodeInstance *v2alpha1.CiliumBGPNodeInstance
		expectedError      bool
		expectedAdverts    PeerAdvertisements
	}{
		{
			name:       "Peer config does not exist for peer in BGPNodeInstance",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
			},
			reqBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes:  []v2alpha1.BGPAdvertisementType{v2alpha1.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{},
		},
		{
			name: "Expecting PodCIDR advertisement for single peer",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes: []v2alpha1.BGPAdvertisementType{v2alpha1.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert},
				},
			},
		},
		{
			name: "Expecting PodCIDR advertisement for dual peers",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red",
						},
					},
					{
						Name: "blue-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-blue",
						},
					},
				},
			},
			reqAdvertTypes: []v2alpha1.BGPAdvertisementType{v2alpha1.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert},
				},
				"blue-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {bluePodCIDRAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {bluePodCIDRAdvert},
				},
			},
		},
		{
			name: "Expecting no advertisement, unknown label",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				// redAdvert, red advertisement not present for this test case
				blueAdvert,
			},
			reqBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes: []v2alpha1.BGPAdvertisementType{v2alpha1.BGPPodCIDRAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: nil, // empty advertisement
					{Afi: "ipv6", Safi: "unicast"}: nil, // empty advertisement
				},
			},
		},
		{
			name: "Expecting PodCIDR and Service advertisement for single peer",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red",
						},
					},
				},
			},
			reqAdvertTypes: []v2alpha1.BGPAdvertisementType{v2alpha1.BGPPodCIDRAdvert, v2alpha1.BGPServiceAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert, redServicePodAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert, redServicePodAdvert},
				},
			},
		},
		{
			name: "Expecting PodCIDR and Service advertisement for dual peers",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			reqBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red",
						},
					},
					{
						Name: "blue-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-blue",
						},
					},
				},
			},
			reqAdvertTypes: []v2alpha1.BGPAdvertisementType{v2alpha1.BGPPodCIDRAdvert, v2alpha1.BGPServiceAdvert},
			expectedAdverts: map[string]PeerFamilyAdvertisements{
				"red-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
					{Afi: "ipv4", Safi: "unicast"}: {redPodCIDRAdvert, redServicePodAdvert},
					{Afi: "ipv6", Safi: "unicast"}: {redPodCIDRAdvert, redServicePodAdvert},
				},
				"blue-peer-65001": map[v2alpha1.CiliumBGPFamily][]v2alpha1.BGPAdvertisement{
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
				PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfig),
				AdvertStore:     store.InitMockStore[*v2alpha1.CiliumBGPAdvertisement](tt.advertisements),
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
