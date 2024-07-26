// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	serviceIPPoolTestLogger = logrus.WithField("unit_test", "reconcilerv2_service")
)

var (
	redSvcKey           = resource.Key{Name: "red-svc", Namespace: "non-default"}
	redLBPoolKey        = resource.Key{Name: "red-lb-pool"}
	redSvcSelector      = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	mismatchSvcSelector = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	ingressV4           = "192.168.0.1"
	ingressV4Prefix     = "192.168.0.1/32"
	ingressV4PoolPrefix = "192.168.0.0/24"
	externalV4          = "192.168.0.2"
	externalV4Prefix    = "192.168.0.2/32"
	clusterV4           = "192.168.0.3"
	clusterV4Prefix     = "192.168.0.3/32"
	ingressV6           = "2001:db8::1"
	ingressV6Prefix     = "2001:db8::1/128"
	ingressV6PoolPrefix = "2001:db8::/64"
	externalV6          = "2001:db8::2"
	externalV6Prefix    = "2001:db8::2/128"
	clusterV6           = "2001:db8::3"
	clusterV6Prefix     = "2001:db8::3/128"

	redLBPool = &v2alpha1.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "red-lb-pool",
			Labels: redSvcSelector.MatchLabels,
		},
		Spec: v2alpha1.CiliumLoadBalancerIPPoolSpec{
			Blocks: []v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
				{
					Cidr: v2alpha1.IPv4orIPv6CIDR(ingressV4PoolPrefix),
				},
				{
					Cidr: v2alpha1.IPv4orIPv6CIDR(ingressV6PoolPrefix),
				},
			},
		},
	}

	redLBSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4,
					},
					{
						IP: ingressV6,
					},
				},
			},
		},
	}
	redLBSvcWithETP = func(eTP slim_corev1.ServiceExternalTrafficPolicy) *slim_corev1.Service {
		cp := redLBSvc.DeepCopy()
		cp.Spec.ExternalTrafficPolicy = eTP
		return cp
	}

	redPeer65001v4LBRPName = PolicyName("red-peer-65001", "ipv4", v2alpha1.BGPServiceAdvert, "red-lb-pool")
	redPeer65001v4LBRP     = &types.RoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV4PoolPrefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001v6LBRPName = PolicyName("red-peer-65001", "ipv6", v2alpha1.BGPServiceAdvert, "red-lb-pool")
	redPeer65001v6LBRP     = &types.RoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV6PoolPrefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redExternalSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeClusterIP,
			ExternalIPs: []string{
				externalV4,
				externalV6,
			},
		},
	}

	redExternalSvcWithETP = func(eTP slim_corev1.ServiceExternalTrafficPolicy) *slim_corev1.Service {
		cp := redExternalSvc.DeepCopy()
		cp.Spec.ExternalTrafficPolicy = eTP
		return cp
	}

	redPeer65001v4ExtRPName = PolicyName("red-peer-65001", "ipv4", v2alpha1.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v4ExtRP     = &types.RoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(externalV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001v6ExtRPName = PolicyName("red-peer-65001", "ipv6", v2alpha1.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v6ExtRP     = &types.RoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(externalV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redClusterSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type:      slim_corev1.ServiceTypeClusterIP,
			ClusterIP: clusterV4,
			ClusterIPs: []string{
				clusterV4,
				clusterV6,
			},
		},
	}

	redClusterSvcWithITP = func(iTP slim_corev1.ServiceInternalTrafficPolicy) *slim_corev1.Service {
		cp := redClusterSvc.DeepCopy()
		cp.Spec.InternalTrafficPolicy = &iTP
		return cp
	}

	redPeer65001v4ClusterRPName = PolicyName("red-peer-65001", "ipv4", v2alpha1.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v4ClusterRP     = &types.RoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(clusterV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001v6ClusterRPName = PolicyName("red-peer-65001", "ipv6", v2alpha1.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v6ClusterRP     = &types.RoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(clusterV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redExternalAndClusterSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type:      slim_corev1.ServiceTypeClusterIP,
			ClusterIP: clusterV4,
			ClusterIPs: []string{
				clusterV4,
				clusterV6,
			},
			ExternalIPs: []string{
				externalV4,
				externalV6,
			},
		},
	}

	redExternalAndClusterSvcWithITP = func(svc *slim_corev1.Service, iTP slim_corev1.ServiceInternalTrafficPolicy) *slim_corev1.Service {
		cp := svc.DeepCopy()
		cp.Spec.InternalTrafficPolicy = &iTP
		return cp
	}

	redExternalAndClusterSvcWithETP = func(svc *slim_corev1.Service, eTP slim_corev1.ServiceExternalTrafficPolicy) *slim_corev1.Service {
		cp := svc.DeepCopy()
		cp.Spec.ExternalTrafficPolicy = eTP
		return cp
	}

	redSvcAdvert = &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
	}

	redSvcAdvertWithAdvertisements = func(adverts ...v2alpha1.BGPAdvertisement) *v2alpha1.CiliumBGPAdvertisement {
		cp := redSvcAdvert.DeepCopy()
		cp.Spec.Advertisements = adverts
		return cp
	}

	lbSvcAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPServiceAdvert,
		Service: &v2alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPLoadBalancerIPAddr},
		},
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
			},
		},
	}
	lbSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v2alpha1.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}

	externalSvcAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPServiceAdvert,
		Service: &v2alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPExternalIPAddr},
		},
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	externalSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v2alpha1.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}

	clusterIPSvcAdvert = v2alpha1.BGPAdvertisement{
		AdvertisementType: v2alpha1.BGPServiceAdvert,
		Service: &v2alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPClusterIPAddr},
		},
		Attributes: &v2alpha1.BGPAttributes{
			Communities: &v2alpha1.BGPCommunities{
				Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	clusterIPSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v2alpha1.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}

	testBGPInstanceConfig = &v2alpha1.CiliumBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v2alpha1.CiliumBGPNodePeer{
			{
				Name:        "red-peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v2alpha1.PeerConfigReference{
					Group: "cilium.io",
					Kind:  "CiliumBGPPeerConfig",
					Name:  "peer-config-red",
				},
			},
		},
	}

	testCiliumNodeConfig = &v2api.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
	}

	eps1Local = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "non-default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      redSvcKey.Name,
				Namespace: redSvcKey.Namespace,
			},
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::1"): {
				NodeName: "node1",
			},
		},
	}

	eps1LocalTerminating = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "non-default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      redSvcKey.Name,
				Namespace: redSvcKey.Namespace,
			},
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName:    "node1",
				Terminating: true,
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::1"): {
				NodeName:    "node1",
				Terminating: true,
			},
		},
	}

	eps1Remote = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      redSvcKey.Name,
				Namespace: redSvcKey.Namespace,
			},
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::2"): {
				NodeName: "node2",
			},
		},
	}

	eps1Mixed = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      redSvcKey.Name,
				Namespace: redSvcKey.Namespace,
			},
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::2"): {
				NodeName: "node2",
			},
		},
	}
)

// Test_ServiceLBReconciler tests reconciliation of service of type load-balancer
func Test_ServiceLBReconciler(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name             string
		peerConfig       []*v2alpha1.CiliumBGPPeerConfig
		advertisements   []*v2alpha1.CiliumBGPAdvertisement
		lbIPPools        []*v2alpha1.CiliumLoadBalancerIPPool
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (LB) with advertisement( empty )",
			peerConfig:     []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redLBSvc},
			lbIPPools:      []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - mismatch labels",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvc},
			lbIPPools:  []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=cluster)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			lbIPPools:  []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{
					redLBPoolKey: {
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on node)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			lbIPPools:  []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			endpoints:  []*k8s.Endpoints{eps1Local},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{
					redLBPoolKey: {
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, mixed ep)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			lbIPPools:  []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			endpoints:  []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{
					redLBPoolKey: {
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on remote)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			lbIPPools:  []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			endpoints:  []*k8s.Endpoints{eps1Remote},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{ // route policies will exists even if there are no local eps
					redLBPoolKey: {
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, backends are terminating)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			lbIPPools:  []*v2alpha1.CiliumLoadBalancerIPPool{redLBPool},
			endpoints:  []*k8s.Endpoints{eps1LocalTerminating},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{ // route policies will exists even if there are no local eps
					redLBPoolKey: {
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			params := ServiceReconcilerIn{
				Logger: serviceIPPoolTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2alpha1.CiliumBGPAdvertisement](tt.advertisements),
					}),
				LBIPPoolStore: store.InitMockStore[*v2alpha1.CiliumLoadBalancerIPPool](tt.lbIPPools),
				SvcDiffStore:  store.InitFakeDiffStore[*slim_corev1.Service](tt.services),
				EPDiffStore:   store.InitFakeDiffStore[*k8s.Endpoints](tt.endpoints),
			}

			svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
			testBGPInstance := instance.NewFakeBGPInstance()

			// reconcile twice to validate idempotency
			for i := 0; i < 2; i++ {
				err := svcReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: testBGPInstanceConfig,
					CiliumNode:    testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, svcReconciler.getMetadata(testBGPInstance))
		})
	}
}

// Test_ServiceExternalIPReconciler tests reconciliation of cluster service with external IP
func Test_ServiceExternalIPReconciler(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name             string
		peerConfig       []*v2alpha1.CiliumBGPPeerConfig
		advertisements   []*v2alpha1.CiliumBGPAdvertisement
		lbIPPools        []*v2alpha1.CiliumLoadBalancerIPPool
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (External) with advertisement( empty )",
			peerConfig:     []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redExternalSvc},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - mismatch labels",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvc},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=cluster)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=local, ep on node)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Local},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=local, mixed ep)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=local, ep on remote)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Remote},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			params := ServiceReconcilerIn{
				Logger: serviceIPPoolTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2alpha1.CiliumBGPAdvertisement](tt.advertisements),
					}),
				LBIPPoolStore: store.InitMockStore[*v2alpha1.CiliumLoadBalancerIPPool](tt.lbIPPools),
				SvcDiffStore:  store.InitFakeDiffStore[*slim_corev1.Service](tt.services),
				EPDiffStore:   store.InitFakeDiffStore[*k8s.Endpoints](tt.endpoints),
			}

			svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
			testBGPInstance := instance.NewFakeBGPInstance()

			// reconcile twice to validate idempotency
			for i := 0; i < 2; i++ {
				err := svcReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: testBGPInstanceConfig,
					CiliumNode:    testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, svcReconciler.getMetadata(testBGPInstance))
		})
	}
}

// Test_ServiceClusterIPReconciler tests reconciliation of cluster service
func Test_ServiceClusterIPReconciler(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name             string
		peerConfig       []*v2alpha1.CiliumBGPPeerConfig
		advertisements   []*v2alpha1.CiliumBGPAdvertisement
		lbIPPools        []*v2alpha1.CiliumLoadBalancerIPPool
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (Cluster) with advertisement( empty )",
			peerConfig:     []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redClusterSvc},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - mismatch labels",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvc},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=cluster)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyCluster)},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on node)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Local},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, mixed ep)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on remote)",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Remote},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			params := ServiceReconcilerIn{
				Logger: serviceIPPoolTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2alpha1.CiliumBGPAdvertisement](tt.advertisements),
					}),
				LBIPPoolStore: store.InitMockStore[*v2alpha1.CiliumLoadBalancerIPPool](tt.lbIPPools),
				SvcDiffStore:  store.InitFakeDiffStore[*slim_corev1.Service](tt.services),
				EPDiffStore:   store.InitFakeDiffStore[*k8s.Endpoints](tt.endpoints),
			}

			svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
			testBGPInstance := instance.NewFakeBGPInstance()

			// reconcile twice to validate idempotency
			for i := 0; i < 2; i++ {
				err := svcReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: testBGPInstanceConfig,
					CiliumNode:    testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, svcReconciler.getMetadata(testBGPInstance))
		})
	}
}

// Test_ServiceAndAdvertisementModifications is a step test, in which each step modifies the advertisement or service parameters.
func Test_ServiceAndAdvertisementModifications(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	peerConfigs := []*v2alpha1.CiliumBGPPeerConfig{redPeerConfig}

	steps := []struct {
		name             string
		upsertAdverts    []*v2alpha1.CiliumBGPAdvertisement
		upsertServices   []*slim_corev1.Service
		upsertEPs        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Initial setup - Service (nil) with advertisement( empty )",
			upsertAdverts:  nil,
			upsertServices: nil,
			upsertEPs:      nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name: "Add service (Cluster, External) with advertisement(Cluster) - matching labels",
			upsertAdverts: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v2alpha1.BGPAdvertisement{
					AdvertisementType: v2alpha1.BGPServiceAdvert,
					Service: &v2alpha1.BGPServiceOptions{
						Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPClusterIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2alpha1.BGPAttributes{
						Communities: &v2alpha1.BGPCommunities{
							Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			upsertServices: []*slim_corev1.Service{redExternalAndClusterSvc},
			expectedMetadata: ServiceReconcilerMetadata{
				// Only cluster IPs are advertised
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update advertisement(Cluster, External) - matching labels",
			upsertAdverts: []*v2alpha1.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v2alpha1.BGPAdvertisement{
					AdvertisementType: v2alpha1.BGPServiceAdvert,
					Service: &v2alpha1.BGPServiceOptions{
						Addresses: []v2alpha1.BGPServiceAddressType{
							v2alpha1.BGPClusterIPAddr,
							v2alpha1.BGPExternalIPAddr,
						},
					},
					Selector: redSvcSelector,
					Attributes: &v2alpha1.BGPAttributes{
						Communities: &v2alpha1.BGPCommunities{
							Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are advertised
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v4ExtRPName:     redPeer65001v4ExtRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
						redPeer65001v6ExtRPName:     redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{
										v2alpha1.BGPClusterIPAddr,
										v2alpha1.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{
										v2alpha1.BGPClusterIPAddr,
										v2alpha1.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update service (Cluster, External) traffic policy local",
			upsertServices: []*slim_corev1.Service{
				redExternalAndClusterSvcWithITP(
					redExternalAndClusterSvcWithETP(redExternalAndClusterSvc, slim_corev1.ServiceExternalTrafficPolicyLocal),
					slim_corev1.ServiceInternalTrafficPolicyLocal),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn, since traffic policy is local and there are no endpoints.
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				LBPoolRoutePolicies:  ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{
										v2alpha1.BGPClusterIPAddr,
										v2alpha1.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{
										v2alpha1.BGPClusterIPAddr,
										v2alpha1.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "Update local endpoints (Cluster, External)",
			upsertEPs: []*k8s.Endpoints{eps1Mixed},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are advertised since there is local endpoint.
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v4ExtRPName:     redPeer65001v4ExtRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
						redPeer65001v6ExtRPName:     redPeer65001v6ExtRP,
					},
				},
				LBPoolRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{
										v2alpha1.BGPClusterIPAddr,
										v2alpha1.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2alpha1.BGPAdvertisement{
							{
								AdvertisementType: v2alpha1.BGPServiceAdvert,
								Service: &v2alpha1.BGPServiceOptions{
									Addresses: []v2alpha1.BGPServiceAddressType{
										v2alpha1.BGPClusterIPAddr,
										v2alpha1.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2alpha1.BGPAttributes{
									Communities: &v2alpha1.BGPCommunities{
										Standard:  []v2alpha1.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2alpha1.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	req := require.New(t)
	advertStore := store.NewMockBGPCPResourceStore[*v2alpha1.CiliumBGPAdvertisement]()
	serviceStore := store.NewFakeDiffStore[*slim_corev1.Service]()
	epStore := store.NewFakeDiffStore[*k8s.Endpoints]()
	lbPoolStore := store.NewMockBGPCPResourceStore[*v2alpha1.CiliumLoadBalancerIPPool]()

	params := ServiceReconcilerIn{
		Logger: serviceIPPoolTestLogger,
		PeerAdvert: NewCiliumPeerAdvertisement(
			PeerAdvertisementIn{
				Logger:          podCIDRTestLogger,
				PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](peerConfigs),
				AdvertStore:     advertStore,
			}),
		LBIPPoolStore: lbPoolStore,
		SvcDiffStore:  serviceStore,
		EPDiffStore:   epStore,
	}

	svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
	testBGPInstance := instance.NewFakeBGPInstance()

	for _, tt := range steps {
		t.Logf("Running step - %s", tt.name)
		for _, advert := range tt.upsertAdverts {
			advertStore.Upsert(advert)
		}

		for _, svc := range tt.upsertServices {
			serviceStore.Upsert(svc)
		}

		for _, ep := range tt.upsertEPs {
			epStore.Upsert(ep)
		}

		err := svcReconciler.Reconcile(context.Background(), ReconcileParams{
			BGPInstance:   testBGPInstance,
			DesiredConfig: testBGPInstanceConfig,
			CiliumNode:    testCiliumNodeConfig,
		})
		req.NoError(err)

		// validate new metadata
		serviceMetadataEqual(req, tt.expectedMetadata, svcReconciler.getMetadata(testBGPInstance))
	}
}

func serviceMetadataEqual(req *require.Assertions, expectedMetadata, runningMetadata ServiceReconcilerMetadata) {
	req.Truef(PeerAdvertisementsEqual(expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements),
		"ServiceAdvertisements mismatch, expected: %v, got: %v", expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements)

	req.Equalf(len(expectedMetadata.ServicePaths), len(runningMetadata.ServicePaths),
		"ServicePaths length mismatch, expected: %v, got: %v", expectedMetadata.ServicePaths, runningMetadata.ServicePaths)

	for svc, expectedSvcPaths := range expectedMetadata.ServicePaths {
		runningSvcPaths, exists := runningMetadata.ServicePaths[svc]
		req.Truef(exists, "Service not found in running: %v", svc)

		runningFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range runningSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			runningFamilyPaths[family] = pathSet
		}

		expectedFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range expectedSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			expectedFamilyPaths[family] = pathSet
		}

		req.Equal(expectedFamilyPaths, runningFamilyPaths)
	}

	req.Equalf(expectedMetadata.LBPoolRoutePolicies, runningMetadata.LBPoolRoutePolicies,
		"LBPoolRoutePolicies mismatch, expected: %v, got: %v", expectedMetadata.LBPoolRoutePolicies, runningMetadata.LBPoolRoutePolicies)

	req.Equalf(expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies,
		"ServiceRoutePolicies mismatch, expected: %v, got: %v", expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies)
}
