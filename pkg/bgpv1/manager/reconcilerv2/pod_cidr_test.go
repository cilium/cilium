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
	podCIDR1v4 = "10.10.1.0/24"
	podCIDR1v6 = "2001:db8:1::/96"
	podCIDR2v4 = "10.10.2.0/24"
	podCIDR2v6 = "2001:db8:2::/96"
	podCIDR3v4 = "10.10.3.0/24"
	podCIDR3v6 = "2001:db8:3::/96"
)

func Test_PodCIDRAdvertisement(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                  string
		peerConfig            []*v2alpha1.CiliumBGPPeerConfig
		advertisements        []*v2alpha1.CiliumBGPAdvertisement
		preconfiguredAdverts  map[types.Family]map[string]struct{}
		testCiliumNode        *v2api.CiliumNode
		testBGPInstanceConfig *v2alpha1.CiliumBGPNodeInstance
		expectedAdverts       map[types.Family]map[string]struct{}
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
			preconfiguredAdverts: map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{
							podCIDR1v4,
							podCIDR2v4,
							podCIDR1v6,
							podCIDR2v6,
						},
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
			expectedAdverts: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
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
			preconfiguredAdverts: map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{
							podCIDR1v4,
							podCIDR2v4,
							podCIDR1v6,
							podCIDR2v6,
						},
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
			expectedAdverts: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
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
			preconfiguredAdverts: map[types.Family]map[string]struct{}{
				// pod cidr 3 is extra advertisement, reconcile should clean this.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR3v4: struct{}{},
					podCIDR3v6: struct{}{},
				},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
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
			expectedAdverts: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
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
			preconfiguredAdverts: map[types.Family]map[string]struct{}{
				// pod cidr 1,2 already advertised, reconcile should clean this as there is no matching pod cidr advertisement.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
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
			expectedAdverts: map[types.Family]map[string]struct{}{
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
			preconfiguredAdverts: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
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
			expectedAdverts: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
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
				pathSet := make(map[string]*types.Path)
				for preAdvert := range preAdverts {
					path := types.NewPathForPrefix(netip.MustParsePrefix(preAdvert))
					path.Family = preAdvertFam
					pathSet[preAdvert] = path
				}
				presetAdverts[preAdvertFam] = pathSet
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
			runningFamilyPaths := make(map[types.Family]map[string]struct{})
			for family, paths := range podCIDRReconciler.getMetadata(testBGPInstance).AFPaths {
				pathSet := make(map[string]struct{})
				for pathKey := range paths {
					pathSet[pathKey] = struct{}{}
				}
				runningFamilyPaths[family] = pathSet
			}

			req.Equal(tt.expectedAdverts, runningFamilyPaths)
		})
	}
}
