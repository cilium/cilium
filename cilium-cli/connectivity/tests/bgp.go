// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/versioncheck"
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

	bgpConnectRetryTimeSeconds = 1
	bgpKeepAliveTimeSeconds    = 1
	bgpHoldTimeSeconds         = 3
)

func BGPAdvertisements(bgpAPIVersion uint8) check.Scenario {
	return &bgpAdvertisements{
		bgpAPIVersion: bgpAPIVersion,
		ScenarioBase:  check.NewScenarioBase(),
	}
}

type bgpAdvertisements struct {
	check.ScenarioBase

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
			neighbors := check.WaitForFRRBGPNeighborsState(ctx, t, &frr, frrPeers, "Established")
			check.AssertFRRBGPNeighborTimers(t, neighbors, frrPeers, bgpKeepAliveTimeSeconds, bgpHoldTimeSeconds)

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
					a.ExecInPod(ctx, a.CurlCommand(echo))
				})
				i++
			}
			//  curl from external echo pods to ClusterIP service IPs
			i = 0
			if status, ok := ct.Feature(features.BPFLBExternalClusterIP); ok && status.Enabled {
				for _, echo := range ct.EchoServices() {
					t.NewAction(s, fmt.Sprintf("curl-echo-service-%s-%d", ipFamily, i), &client, echo, ipFamily).Run(func(a *check.Action) {
						a.ExecInPod(ctx, a.CurlCommand(echo))
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
	clientV2Alpha1 := t.Context().K8sClient().CiliumClientset.CiliumV2alpha1()
	clientV2 := t.Context().K8sClient().CiliumClientset.CiliumV2()

	if s.bgpAPIVersion == 1 {
		check.DeleteK8sResourceWithWait(ctx, t, clientV2Alpha1.CiliumBGPPeeringPolicies(), bgpPeeringPolicyName)
	} else {
		if versioncheck.MustCompile(">=1.18.0")(t.Context().CiliumVersion) {
			// cleanup v2 resources
			check.DeleteK8sResourceWithWait(ctx, t, clientV2.CiliumBGPClusterConfigs(), bgpClusterConfigName)
			check.DeleteK8sResourceWithWait(ctx, t, clientV2.CiliumBGPPeerConfigs(), bgpPeerConfigName)
			check.DeleteK8sResourceWithWait(ctx, t, clientV2.CiliumBGPAdvertisements(), bgpAdvertisementName)
		} else {
			// cleanup v2alpha1 resources
			check.DeleteK8sResourceWithWait(ctx, t, clientV2Alpha1.CiliumBGPClusterConfigs(), bgpClusterConfigName)
			check.DeleteK8sResourceWithWait(ctx, t, clientV2Alpha1.CiliumBGPPeerConfigs(), bgpPeerConfigName)
			check.DeleteK8sResourceWithWait(ctx, t, clientV2Alpha1.CiliumBGPAdvertisements(), bgpAdvertisementName)
		}
	}
}

func (s *bgpAdvertisements) configureBGPv1Peering(ctx context.Context, t *check.Test, ipFamily features.IPFamily) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.CiliumV2alpha1()
	s.deleteK8sResources(ctx, t)

	peeringPolicy := &v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeeringPolicyName,
		},
		Spec: v2alpha1.CiliumBGPPeeringPolicySpec{
			VirtualRouters: []v2alpha1.CiliumBGPVirtualRouter{
				{
					LocalASN:      bgpCiliumASN,
					ExportPodCIDR: ptr.To[bool](true),
					ServiceSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"kind": "echo"},
					},
					ServiceAdvertisements: []v2alpha1.BGPServiceAddressType{
						v2alpha1.BGPClusterIPAddr,
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
			v2alpha1.CiliumBGPNeighbor{
				PeerAddress:             frr.Address(ipFamily) + prefix,
				PeerASN:                 bgpFRRASN,
				ConnectRetryTimeSeconds: ptr.To[int32](bgpConnectRetryTimeSeconds),
				KeepAliveTimeSeconds:    ptr.To[int32](bgpKeepAliveTimeSeconds),
				HoldTimeSeconds:         ptr.To[int32](bgpHoldTimeSeconds),
				AdvertisedPathAttributes: []v2alpha1.CiliumBGPPathAttributes{
					{
						SelectorType: v2alpha1.PodCIDRSelectorName,
						Communities: &v2alpha1.BGPCommunities{
							Standard: []v2alpha1.BGPStandardCommunity{bgpCommunityPodCIDR},
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
	s.deleteK8sResources(ctx, t)

	if versioncheck.MustCompile(">=1.18.0")(t.Context().CiliumVersion) {
		// use v2 API version
		s.configureBGPv2PeeringV2(ctx, t, ipFamily)
	} else {
		// use v2alpha1 API version
		s.configureBGPv2PeeringV2Alpha1(ctx, t, ipFamily)
	}
}

func (s *bgpAdvertisements) configureBGPv2PeeringV2(ctx context.Context, t *check.Test, ipFamily features.IPFamily) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.CiliumV2()

	// configure advertisement
	advertisement := &v2.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   bgpAdvertisementName,
			Labels: map[string]string{"test": s.Name()},
		},
		Spec: v2.CiliumBGPAdvertisementSpec{
			Advertisements: []v2.BGPAdvertisement{
				{
					AdvertisementType: v2.BGPPodCIDRAdvert,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard: []v2.BGPStandardCommunity{bgpCommunityPodCIDR},
						},
					},
				},
				{
					AdvertisementType: v2.BGPServiceAdvert,
					Service: &v2.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"kind": "echo"},
					},
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard: []v2.BGPStandardCommunity{bgpCommunityService},
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
	peerConfig := &v2.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeerConfigName,
		},
		Spec: v2.CiliumBGPPeerConfigSpec{
			Timers: &v2.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](bgpConnectRetryTimeSeconds),
				KeepAliveTimeSeconds:    ptr.To[int32](bgpKeepAliveTimeSeconds),
				HoldTimeSeconds:         ptr.To[int32](bgpHoldTimeSeconds),
			},
			Families: []v2.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
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
	clusterConfig := &v2.CiliumBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpClusterConfigName,
		},
		Spec: v2.CiliumBGPClusterConfigSpec{
			BGPInstances: []v2.CiliumBGPInstance{
				{
					Name:     "test-instance",
					LocalASN: ptr.To[int64](bgpCiliumASN),
				},
			},
		},
	}
	for _, frr := range ct.FRRPods() {
		clusterConfig.Spec.BGPInstances[0].Peers = append(clusterConfig.Spec.BGPInstances[0].Peers,
			v2.CiliumBGPPeer{
				Name:        "peer-" + frr.Address(ipFamily),
				PeerAddress: ptr.To[string](frr.Address(ipFamily)),
				PeerASN:     ptr.To[int64](bgpFRRASN),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: peerConfig.Name,
				},
			})
	}
	_, err = client.CiliumBGPClusterConfigs().Create(ctx, clusterConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CiliumBGPClusterConfig: %v", err)
	}
}

func (s *bgpAdvertisements) configureBGPv2PeeringV2Alpha1(ctx context.Context, t *check.Test, ipFamily features.IPFamily) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.CiliumV2alpha1()

	// configure advertisement
	advertisement := &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   bgpAdvertisementName,
			Labels: map[string]string{"test": s.Name()},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				{
					AdvertisementType: v2alpha1.BGPPodCIDRAdvert,
					Attributes: &v2alpha1.BGPAttributes{
						Communities: &v2alpha1.BGPCommunities{
							Standard: []v2alpha1.BGPStandardCommunity{bgpCommunityPodCIDR},
						},
					},
				},
				{
					AdvertisementType: v2alpha1.BGPServiceAdvert,
					Service: &v2alpha1.BGPServiceOptions{
						Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPClusterIPAddr},
					},
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"kind": "echo"},
					},
					Attributes: &v2alpha1.BGPAttributes{
						Communities: &v2alpha1.BGPCommunities{
							Standard: []v2alpha1.BGPStandardCommunity{bgpCommunityService},
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
	peerConfig := &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeerConfigName,
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Timers: &v2alpha1.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](bgpConnectRetryTimeSeconds),
				KeepAliveTimeSeconds:    ptr.To[int32](bgpKeepAliveTimeSeconds),
				HoldTimeSeconds:         ptr.To[int32](bgpHoldTimeSeconds),
			},
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
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
	clusterConfig := &v2alpha1.CiliumBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpClusterConfigName,
		},
		Spec: v2alpha1.CiliumBGPClusterConfigSpec{
			BGPInstances: []v2alpha1.CiliumBGPInstance{
				{
					Name:     "test-instance",
					LocalASN: ptr.To[int64](bgpCiliumASN),
				},
			},
		},
	}
	for _, frr := range ct.FRRPods() {
		clusterConfig.Spec.BGPInstances[0].Peers = append(clusterConfig.Spec.BGPInstances[0].Peers,
			v2alpha1.CiliumBGPPeer{
				Name:        "peer-" + frr.Address(ipFamily),
				PeerAddress: ptr.To[string](frr.Address(ipFamily)),
				PeerASN:     ptr.To[int64](bgpFRRASN),
				PeerConfigRef: &v2alpha1.PeerConfigReference{
					Name: peerConfig.Name,
				},
			})
	}
	_, err = client.CiliumBGPClusterConfigs().Create(ctx, clusterConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CiliumBGPClusterConfig: %v", err)
	}
}
