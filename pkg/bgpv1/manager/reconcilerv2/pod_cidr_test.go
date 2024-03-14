// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

var (
	podCIDRTestLogger = logrus.WithField("unit_test", "reconcilerv2_podcidr")
)

// test fixtures
var (
	podCIDR1 = "10.10.1.0/24"
	podCIDR2 = "10.10.2.0/24"
	podCIDR3 = "10.10.3.0/24"
)

func Test_PodCIDRAdvertisement(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                  string
		peerConfig            []*v2alpha1.CiliumBGPPeerConfig
		advertisements        []*v2alpha1.CiliumBGPAdvertisement
		preconfiguredAdverts  map[types.Family][]string
		testCiliumNode        *v2api.CiliumNode
		testBGPInstanceConfig *v2alpha1.CiliumBGPNodeInstance
		expectedAdverts       map[types.Family][]string
	}{
		{
			name: "pod cidr advertisement with no preconfigured advertisements",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredAdverts: map[types.Family][]string{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1, podCIDR2},
					},
				},
			},
			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
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
			expectedAdverts: map[types.Family][]string{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
			},
		},
		{
			name: "pod cidr advertisement with no preconfigured advertisements - two peers",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredAdverts: map[types.Family][]string{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1, podCIDR2},
					},
				},
			},
			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
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
			expectedAdverts: map[types.Family][]string{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
			},
		},
		{
			name: "pod cidr advertisement - cleanup old pod cidr",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredAdverts: map[types.Family][]string{
				// pod cidr 3 is extra advertisement, reconcile should clean this.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR3},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1, podCIDR2},
					},
				},
			},
			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
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
			expectedAdverts: map[types.Family][]string{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
			},
		},
		{
			name: "pod cidr advertisement - disable",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				//no pod cidr advertisement configured
				//redPodCIDRAdvert,
				//bluePodCIDRAdvert,
			},
			preconfiguredAdverts: map[types.Family][]string{
				// pod cidr 1,2 already advertised, reconcile should clean this as there is no matching pod cidr advertisement.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1, podCIDR2},
					},
				},
			},
			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
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
			expectedAdverts: map[types.Family][]string{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
		},
		{
			name: "pod cidr advertisement - v4 only",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfigV4,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,
				//bluePodCIDRAdvert,
			},
			preconfiguredAdverts: map[types.Family][]string{
				// pod cidr 1,2 already advertised, reconcile should clean v6 advertisement.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1, podCIDR2},
					},
				},
			},
			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name: "red-peer-65001",
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Group: "cilium.io",
							Kind:  "CiliumBGPPeerConfig",
							Name:  "peer-config-red-v4",
						},
					},
				},
			},
			expectedAdverts: map[types.Family][]string{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {podCIDR1, podCIDR2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			// initialize pod cidr reconciler
			p := PodCIDRReconcilerIn{
				Logger: podCIDRTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2alpha1.CiliumBGPAdvertisement](tt.advertisements),
					}),
				DaemonConfig: &option.DaemonConfig{IPAM: "Kubernetes"},
			}
			podCIDRReconciler := NewPodCIDRReconciler(p).Reconciler.(*PodCIDRReconciler)

			// preconfigure advertisements
			testBGPInstance := instance.NewFakeBGPInstance()

			presetAdverts := make(AFPathsMap)
			for preAdvertFam, preAdverts := range tt.preconfiguredAdverts {
				var pathList []*types.Path
				for _, preAdvert := range preAdverts {
					path := types.NewPathForPrefix(netip.MustParsePrefix(preAdvert))
					path.Family = preAdvertFam
					pathList = append(pathList, path)
				}
				presetAdverts[preAdvertFam] = pathList
			}
			podCIDRReconciler.setMetadata(testBGPInstance, PodCIDRReconcilerMetadata{presetAdverts})

			// reconcile pod cidr
			// run reconciler twice to ensure idempotency
			for i := 0; i < 2; i++ {
				err := podCIDRReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: tt.testBGPInstanceConfig,
					CiliumNode:    tt.testCiliumNode,
				})
				req.NoError(err)
			}

			// check if the advertisements are as expected
			expectedAdverts := make(AFPathsMap)
			for expectedFam, expectedAdvertsList := range tt.expectedAdverts {
				var pathList []*types.Path
				for _, expectedAdvert := range expectedAdvertsList {
					pathList = append(pathList, types.NewPathForPrefix(netip.MustParsePrefix(expectedAdvert)))
				}
				expectedAdverts[expectedFam] = pathList
			}

			requireEqualPodCIDRMetadata(req, expectedAdverts, podCIDRReconciler.getMetadata(testBGPInstance).AFPaths)
		})
	}
}

func requireEqualPodCIDRMetadata(req *require.Assertions, expected, running AFPathsMap) {
	expectedFamSet := sets.New[types.Family]()
	runningFamSet := sets.New[types.Family]()

	for fam := range expected {
		expectedFamSet.Insert(fam)
	}

	for fam := range running {
		runningFamSet.Insert(fam)
	}

	req.Truef(runningFamSet.Equal(expectedFamSet), "expected: %v, running: %v", expectedFamSet, runningFamSet)

	for fam := range expected {
		expectedPrefixSet := sets.New[string]()
		runningPrefixSet := sets.New[string]()

		for _, path := range expected[fam] {
			expectedPrefixSet.Insert(path.NLRI.String())
		}

		for _, path := range running[fam] {
			runningPrefixSet.Insert(path.NLRI.String())
		}

		req.Truef(runningPrefixSet.Equal(expectedPrefixSet), "expected: %v, running: %v", expectedPrefixSet, runningPrefixSet)
	}
}
