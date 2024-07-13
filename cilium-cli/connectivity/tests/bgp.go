// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	bgpPeeringPolicyName = "test-bgp-peering-policy"
	bgpAdvertisementName = "test-bgp-advertisement"
	bgpPeerConfigName    = "test-bgp-peer-config"
	bgpClusterConfigName = "test-bgp-cluster-config"

	bgpCiliumASN = 65001
	bgpFRRASN    = 65000

	bgpCommunityPodCIDR = "65001:100"
	bgpCommunityService = "65001:200"
)

func BGPAdvertisements(bgpAPIVersion uint8) check.Scenario {
	return &bgpAdvertisements{
		bgpAPIVersion: bgpAPIVersion,
	}
}

type bgpAdvertisements struct {
	bgpAPIVersion uint8
}

func (s *bgpAdvertisements) Name() string {
	return fmt.Sprintf("bgpv%d-advertisements", s.bgpAPIVersion)
}

func (s *bgpAdvertisements) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	t.ForEachIPFamily(func(ipFamily features.IPFamily) {
		defer func() {
			s.cleanup(ctx, t)
		}()

		// configure FRR
		frrPeers := ct.InternalNodeIPAddresses(ipFamily)
		frrConfig := check.RenderFRRBGPPeeringConfig(t, check.FRRBGPPeeringParams{
			LocalASN: bgpFRRASN,
			Peers:    frrPeers,
		})
		for _, frr := range ct.FRRPods() {
			check.ApplyFRRConfig(ctx, t, &frr, frrConfig)
		}

		// configure BGP on Cilium
		if s.bgpAPIVersion == 1 {
			s.configureBGPv1Peering(ctx, t, ipFamily)
		} else {
			s.configureBGPv2Peering(ctx, t, ipFamily)
		}

		// wait for BGP peers and expected prefixes
		podCIDRPrefixes := ct.PodCIDRPrefixes(ipFamily)
		svcPrefixes := ct.EchoServicePrefixes(ipFamily)
		for _, frr := range ct.FRRPods() {
			check.WaitForFRRBGPNeighborsState(ctx, t, &frr, frrPeers, "Established")

			frrPrefixes := check.WaitForFRRBGPPrefixes(ctx, t, &frr, podCIDRPrefixes, ipFamily)
			check.AssertFRRBGPCommunity(t, frrPrefixes, podCIDRPrefixes, bgpCommunityPodCIDR)

			frrPrefixes = check.WaitForFRRBGPPrefixes(ctx, t, &frr, svcPrefixes, ipFamily)
			if s.bgpAPIVersion != 1 { // BGPv1 does not support path attributes for ClusterIP service advertisements
				check.AssertFRRBGPCommunity(t, frrPrefixes, svcPrefixes, bgpCommunityService)
			}
		}

		for _, client := range ct.ExternalEchoPods() {
			// curl from external echo pods to in-cluster echo pods
			i := 0
			for _, echo := range ct.EchoPods() {
				t.NewAction(s, fmt.Sprintf("curl-echo-pod-%s-%d", ipFamily, i), &client, echo, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, ipFamily))
				})
				i++
			}
			//  curl from external echo pods to ClusterIP service IPs
			i = 0
			if status, ok := ct.Feature(features.BPFLBExternalClusterIP); ok && status.Enabled {
				for _, echo := range ct.EchoServices() {
					t.NewAction(s, fmt.Sprintf("curl-echo-service-%s-%d", ipFamily, i), &client, echo, ipFamily).Run(func(a *check.Action) {
						a.ExecInPod(ctx, ct.CurlCommand(echo, ipFamily))
					})
					i++
				}
			}
		}
	})
}

func (s *bgpAdvertisements) cleanup(ctx context.Context, t *check.Test) {
	if t.Failed() {
		for _, frr := range t.Context().FRRPods() {
			check.DumpFRRBGPState(ctx, t, &frr)
		}
	}

	// delete test-configured K8s resources
	s.deleteK8sResources(ctx, t)

	// clear FRR config
	for _, frr := range t.Context().FRRPods() {
		check.ClearFRRConfig(ctx, t, &frr)
	}
}

func (s *bgpAdvertisements) deleteK8sResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient().CiliumClientset.CiliumV2alpha1()

	if s.bgpAPIVersion == 1 {
		check.DeleteK8sResourceWithWait(ctx, t, client.CiliumBGPPeeringPolicies(), bgpPeeringPolicyName)
	} else {
		check.DeleteK8sResourceWithWait(ctx, t, client.CiliumBGPClusterConfigs(), bgpClusterConfigName)
		check.DeleteK8sResourceWithWait(ctx, t, client.CiliumBGPPeerConfigs(), bgpPeerConfigName)
		check.DeleteK8sResourceWithWait(ctx, t, client.CiliumBGPAdvertisements(), bgpAdvertisementName)
	}
}

func (s *bgpAdvertisements) configureBGPv1Peering(ctx context.Context, t *check.Test, ipFamily features.IPFamily) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.CiliumV2alpha1()
	s.deleteK8sResources(ctx, t)

	peeringPolicy := &ciliumv2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeeringPolicyName,
		},
		Spec: ciliumv2alpha1.CiliumBGPPeeringPolicySpec{
			VirtualRouters: []ciliumv2alpha1.CiliumBGPVirtualRouter{
				{
					LocalASN:      bgpCiliumASN,
					ExportPodCIDR: ptr.To[bool](true),
					ServiceSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"kind": "echo"},
					},
					ServiceAdvertisements: []ciliumv2alpha1.BGPServiceAddressType{
						ciliumv2alpha1.BGPClusterIPAddr,
					},
				},
			},
		},
	}
	prefix := "/32"
	if ipFamily == features.IPFamilyV6 {
		prefix = "/128"
	}
	for _, frr := range ct.FRRPods() {
		peeringPolicy.Spec.VirtualRouters[0].Neighbors = append(peeringPolicy.Spec.VirtualRouters[0].Neighbors,
			ciliumv2alpha1.CiliumBGPNeighbor{
				PeerAddress:             frr.Address(ipFamily) + prefix,
				PeerASN:                 bgpFRRASN,
				ConnectRetryTimeSeconds: ptr.To[int32](1),
				KeepAliveTimeSeconds:    ptr.To[int32](1),
				HoldTimeSeconds:         ptr.To[int32](3),
				AdvertisedPathAttributes: []ciliumv2alpha1.CiliumBGPPathAttributes{
					{
						SelectorType: ciliumv2alpha1.PodCIDRSelectorName,
						Communities: &ciliumv2alpha1.BGPCommunities{
							Standard: []ciliumv2alpha1.BGPStandardCommunity{bgpCommunityPodCIDR},
						},
					},
				},
			})
	}
	_, err := client.CiliumBGPPeeringPolicies().Create(ctx, peeringPolicy, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CiliumBGPPeeringPolicy: %v", err)
	}
}

func (s *bgpAdvertisements) configureBGPv2Peering(ctx context.Context, t *check.Test, ipFamily features.IPFamily) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.CiliumV2alpha1()
	s.deleteK8sResources(ctx, t)

	// configure advertisement
	advertisement := &ciliumv2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   bgpAdvertisementName,
			Labels: map[string]string{"test": s.Name()},
		},
		Spec: ciliumv2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []ciliumv2alpha1.BGPAdvertisement{
				{
					AdvertisementType: ciliumv2alpha1.BGPPodCIDRAdvert,
					Attributes: &ciliumv2alpha1.BGPAttributes{
						Communities: &ciliumv2alpha1.BGPCommunities{
							Standard: []ciliumv2alpha1.BGPStandardCommunity{bgpCommunityPodCIDR},
						},
					},
				},
				{
					AdvertisementType: ciliumv2alpha1.BGPServiceAdvert,
					Service: &ciliumv2alpha1.BGPServiceOptions{
						Addresses: []ciliumv2alpha1.BGPServiceAddressType{ciliumv2alpha1.BGPClusterIPAddr},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"kind": "echo"},
					},
					Attributes: &ciliumv2alpha1.BGPAttributes{
						Communities: &ciliumv2alpha1.BGPCommunities{
							Standard: []ciliumv2alpha1.BGPStandardCommunity{bgpCommunityService},
						},
					},
				},
			},
		},
	}
	_, err := client.CiliumBGPAdvertisements().Create(ctx, advertisement, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CiliumBGPAdvertisement: %v", err)
	}

	// configure peer config
	peerConfig := &ciliumv2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeerConfigName,
		},
		Spec: ciliumv2alpha1.CiliumBGPPeerConfigSpec{
			Timers: &ciliumv2alpha1.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](1),
				KeepAliveTimeSeconds:    ptr.To[int32](1),
				HoldTimeSeconds:         ptr.To[int32](3),
			},
			Families: []ciliumv2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: ciliumv2alpha1.CiliumBGPFamily{
						Afi:  ipFamily.String(),
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: advertisement.Labels,
					},
				},
			},
		},
	}
	_, err = client.CiliumBGPPeerConfigs().Create(ctx, peerConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CiliumBGPPeerConfig: %v", err)
	}

	// configure cluster config
	clusterConfig := &ciliumv2alpha1.CiliumBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpClusterConfigName,
		},
		Spec: ciliumv2alpha1.CiliumBGPClusterConfigSpec{
			BGPInstances: []ciliumv2alpha1.CiliumBGPInstance{
				{
					Name:     "test-instance",
					LocalASN: ptr.To[int64](bgpCiliumASN),
				},
			},
		},
	}
	for _, frr := range ct.FRRPods() {
		clusterConfig.Spec.BGPInstances[0].Peers = append(clusterConfig.Spec.BGPInstances[0].Peers,
			ciliumv2alpha1.CiliumBGPPeer{
				Name:        "peer-" + frr.Address(ipFamily),
				PeerAddress: ptr.To[string](frr.Address(ipFamily)),
				PeerASN:     ptr.To[int64](bgpFRRASN),
				PeerConfigRef: &ciliumv2alpha1.PeerConfigReference{
					Name: peerConfig.Name,
				},
			})
	}
	_, err = client.CiliumBGPClusterConfigs().Create(ctx, clusterConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CiliumBGPClusterConfig: %v", err)
	}
}
