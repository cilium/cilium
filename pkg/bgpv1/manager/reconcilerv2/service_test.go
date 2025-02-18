// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"maps"
	"net/netip"
	"slices"
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
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	serviceReconcilerTestLogger = logrus.WithField("unit_test", "reconcilerv2_service")
)

var (
	redSvcKey           = resource.Key{Name: "red-svc", Namespace: "non-default"}
	redSvc2Key          = resource.Key{Name: "red-svc2", Namespace: "non-default"}
	redSvcSelector      = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	mismatchSvcSelector = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	ingressV4           = "192.168.0.1"
	ingressV4Prefix     = "192.168.0.1/32"
	externalV4          = "192.168.0.2"
	externalV4Prefix    = "192.168.0.2/32"
	clusterV4           = "192.168.0.3"
	clusterV4Prefix     = "192.168.0.3/32"
	ingressV6           = "2001:db8::1"
	ingressV6Prefix     = "2001:db8::1/128"
	externalV6          = "2001:db8::2"
	externalV6Prefix    = "2001:db8::2/128"
	clusterV6           = "2001:db8::3"
	clusterV6Prefix     = "2001:db8::3/128"

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
	redLBSvc2 = func() *slim_corev1.Service {
		cp := redLBSvc.DeepCopy()
		cp.Name = redLBSvc.Name + "2"
		return cp
	}

	localPrefHigh             = int64(200)
	redPeer65001BgpAttributes = &v2.BGPAttributes{
		Communities: &v2.BGPCommunities{
			Standard:  []v2.BGPStandardCommunity{"101:101"},
			Large:     []v2.BGPLargeCommunity{"1111:1111:1111"},
			WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
		},
		LocalPreference: &localPrefHigh,
	}

	localPrefLow               = int64(50)
	redPeer65001BgpAttributes2 = &v2.BGPAttributes{
		Communities: &v2.BGPCommunities{
			Standard:  []v2.BGPStandardCommunity{"202:202"},
			Large:     []v2.BGPLargeCommunity{"2222:2222:2222"},
			WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
		},
		LocalPreference: &localPrefLow,
	}

	redPeer65001BgpAttributes3 = &v2.BGPAttributes{
		Communities: &v2.BGPCommunities{
			Standard: []v2.BGPStandardCommunity{"202:202", "303:303"},
			Large:    []v2.BGPLargeCommunity{"2222:2222:2222", "3333:3333:3333"},
		},
		LocalPreference: &localPrefLow,
	}

	redPeer65001v4LBRPName = PolicyName("red-peer-65001", "ipv4", v2.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v4LBRP     = &types.RoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV4Prefix),
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
	redPeer65001Svc2v4LBRPName = PolicyName("red-peer-65001", "ipv4", v2.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v4LBRP     = func() *types.RoutePolicy {
		return &types.RoutePolicy{
			Name:       redPeer65001Svc2v4LBRPName,
			Type:       types.RoutePolicyTypeExport,
			Statements: redPeer65001v4LBRP.Statements,
		}
	}

	redPeer65001v6LBRPName = PolicyName("red-peer-65001", "ipv6", v2.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v6LBRP     = &types.RoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV6Prefix),
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
	redPeer65001Svc2v6LBRPName = PolicyName("red-peer-65001", "ipv6", v2.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v6LBRP     = func() *types.RoutePolicy {
		return &types.RoutePolicy{
			Name:       redPeer65001Svc2v6LBRPName,
			Type:       types.RoutePolicyTypeExport,
			Statements: redPeer65001v6LBRP.Statements,
		}
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

	redPeer65001v4ExtRPName = PolicyName("red-peer-65001", "ipv4", v2.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
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

	redPeer65001v6ExtRPName = PolicyName("red-peer-65001", "ipv6", v2.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
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

	redPeer65001v4ClusterRPName = PolicyName("red-peer-65001", "ipv4", v2.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
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

	redPeer65001v6ClusterRPName = PolicyName("red-peer-65001", "ipv6", v2.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
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

	redSvcAdvert = &v2.CiliumBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-podCIDR-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
	}

	redSvcAdvertWithAdvertisements = func(adverts ...v2.BGPAdvertisement) *v2.CiliumBGPAdvertisement {
		cp := redSvcAdvert.DeepCopy()
		cp.Spec.Advertisements = adverts
		return cp
	}

	lbSvcAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPServiceAdvert,
		Service: &v2.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	lbSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v2.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}

	lbSvcAdvertWithSelectorAttributes = func(selector *slim_metav1.LabelSelector, attributes *v2.BGPAttributes) v2.BGPAdvertisement {
		cp := lbSvcAdvertWithSelector(selector)
		cp.Attributes = attributes
		return cp
	}

	externalSvcAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPServiceAdvert,
		Service: &v2.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPExternalIPAddr},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	externalSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v2.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}

	externalSvcAdvertWithSelectorAttributes = func(selector *slim_metav1.LabelSelector, attributes *v2.BGPAttributes) v2.BGPAdvertisement {
		cp := externalSvcAdvertWithSelector(selector)
		cp.Attributes = attributes
		return cp
	}

	clusterIPSvcAdvert = v2.BGPAdvertisement{
		AdvertisementType: v2.BGPServiceAdvert,
		Service: &v2.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	clusterIPSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v2.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}

	clusterIPSvcAdvertWithSelectorAttributes = func(selector *slim_metav1.LabelSelector, attributes *v2.BGPAttributes) v2.BGPAdvertisement {
		cp := clusterIPSvcAdvertWithSelector(selector)
		cp.Attributes = attributes
		return cp
	}

	testBGPInstanceConfig = &v2.CiliumBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v2.CiliumBGPNodePeer{
			{
				Name:        "red-peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-config-red",
				},
			},
		},
	}

	testCiliumNodeConfig = &v2.CiliumNode{
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
		peerConfig       []*v2.CiliumBGPPeerConfig
		advertisements   []*v2.CiliumBGPAdvertisement
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (LB) with advertisement( empty )",
			peerConfig:     []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redLBSvc},
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
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - mismatch labels",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvc},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=cluster)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on node)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Local},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, mixed ep)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on remote)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Remote},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (LB) with advertisement(LB) - matching labels (eTP=local, backends are terminating)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1LocalTerminating},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
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
				Logger: serviceReconcilerTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
					}),
				SvcDiffStore: store.InitFakeDiffStore[*slim_corev1.Service](tt.services),
				EPDiffStore:  store.InitFakeDiffStore[*k8s.Endpoints](tt.endpoints),
			}

			svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
			testBGPInstance := instance.NewFakeBGPInstance()
			svcReconciler.Init(testBGPInstance)
			defer svcReconciler.Cleanup(testBGPInstance)

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

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

			// validate that advertised policies match expected attributes
			advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.expectedMetadata.ServiceRoutePolicies)
		})
	}
}

// Test_ServiceExternalIPReconciler tests reconciliation of cluster service with external IP
func Test_ServiceExternalIPReconciler(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name             string
		peerConfig       []*v2.CiliumBGPPeerConfig
		advertisements   []*v2.CiliumBGPAdvertisement
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (External) with advertisement( empty )",
			peerConfig:     []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redExternalSvc},
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
			},
		},
		{
			name:       "Service (External) with advertisement(External) - mismatch labels",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvc},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=cluster)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=local, ep on node)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Local},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=local, mixed ep)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with advertisement(External) - matching labels (eTP=local, ep on remote)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Remote},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (External) with overlapping advertisement(External) - matching labels (eTP=cluster)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(
					externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
					externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
					externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes3),
				),
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
						redPeer65001v4ExtRPName: &types.RoutePolicy{
							Name: redPeer65001v4ExtRP.Name,
							Type: redPeer65001v4ExtRP.Type,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: redPeer65001v4ExtRP.Statements[0].Conditions,
									Actions: types.RoutePolicyActions{
										RouteAction:         types.RoutePolicyActionAccept,
										AddCommunities:      []string{"101:101", "202:202", "303:303", "no-export"},
										AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222", "3333:3333:3333"},
										SetLocalPreference:  &localPrefHigh,
									},
								},
							},
						},
						redPeer65001v6ExtRPName: &types.RoutePolicy{
							Name: redPeer65001v6ExtRP.Name,
							Type: redPeer65001v6ExtRP.Type,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: redPeer65001v6ExtRP.Statements[0].Conditions,
									Actions: types.RoutePolicyActions{
										RouteAction:         types.RoutePolicyActionAccept,
										AddCommunities:      []string{"101:101", "202:202", "303:303", "no-export"},
										AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222", "3333:3333:3333"},
										SetLocalPreference:  &localPrefHigh,
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
							externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
							externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes3),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
							externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
							externalSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes3),
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
				Logger: serviceReconcilerTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
					}),
				SvcDiffStore: store.InitFakeDiffStore[*slim_corev1.Service](tt.services),
				EPDiffStore:  store.InitFakeDiffStore[*k8s.Endpoints](tt.endpoints),
			}

			svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
			testBGPInstance := instance.NewFakeBGPInstance()
			svcReconciler.Init(testBGPInstance)
			defer svcReconciler.Cleanup(testBGPInstance)

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

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

			// validate that advertised policies match expected attributes
			advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.expectedMetadata.ServiceRoutePolicies)
		})
	}
}

// Test_ServiceClusterIPReconciler tests reconciliation of cluster service
func Test_ServiceClusterIPReconciler(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name             string
		peerConfig       []*v2.CiliumBGPPeerConfig
		advertisements   []*v2.CiliumBGPAdvertisement
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (Cluster) with advertisement( empty )",
			peerConfig:     []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redClusterSvc},
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
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - mismatch labels",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvc},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=cluster)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyCluster)},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on node)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Local},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, mixed ep)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on remote)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:  []*k8s.Endpoints{eps1Remote},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:       "Service (Cluster) with overlapping advertisement(Cluster) - matching labels (iTP=cluster)",
			peerConfig: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			services:   []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyCluster)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(
					clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
					clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
					clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes3),
				),
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
						redPeer65001v4ClusterRPName: &types.RoutePolicy{
							Name: redPeer65001v4ClusterRP.Name,
							Type: redPeer65001v4ClusterRP.Type,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: redPeer65001v4ClusterRP.Statements[0].Conditions,
									Actions: types.RoutePolicyActions{
										RouteAction:         types.RoutePolicyActionAccept,
										AddCommunities:      []string{"101:101", "202:202", "303:303", "no-export"},
										AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222", "3333:3333:3333"},
										SetLocalPreference:  &localPrefHigh,
									},
								},
							},
						},
						redPeer65001v6ClusterRPName: &types.RoutePolicy{
							Name: redPeer65001v6ClusterRP.Name,
							Type: redPeer65001v6ClusterRP.Type,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: redPeer65001v6ClusterRP.Statements[0].Conditions,
									Actions: types.RoutePolicyActions{
										RouteAction:         types.RoutePolicyActionAccept,
										AddCommunities:      []string{"101:101", "202:202", "303:303", "no-export"},
										AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222", "3333:3333:3333"},
										SetLocalPreference:  &localPrefHigh,
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
							clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
							clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes3),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
							clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
							clusterIPSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes3),
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
				Logger: serviceReconcilerTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
					}),
				SvcDiffStore: store.InitFakeDiffStore[*slim_corev1.Service](tt.services),
				EPDiffStore:  store.InitFakeDiffStore[*k8s.Endpoints](tt.endpoints),
			}

			svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
			testBGPInstance := instance.NewFakeBGPInstance()
			svcReconciler.Init(testBGPInstance)
			defer svcReconciler.Cleanup(testBGPInstance)

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

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

			// validate that advertised policies match expected attributes
			advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.expectedMetadata.ServiceRoutePolicies)
		})
	}
}

// Test_ServiceAndAdvertisementModifications is a step test, in which each step modifies the advertisement or service parameters.
func Test_ServiceAndAdvertisementModifications(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	peerConfigs := []*v2.CiliumBGPPeerConfig{redPeerConfig}

	steps := []struct {
		name             string
		upsertAdverts    []*v2.CiliumBGPAdvertisement
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
			upsertAdverts: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v2.BGPAdvertisement{
					AdvertisementType: v2.BGPServiceAdvert,
					Service: &v2.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
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
			upsertAdverts: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v2.BGPAdvertisement{
					AdvertisementType: v2.BGPServiceAdvert,
					Service: &v2.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
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
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
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
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
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
	advertStore := store.NewMockBGPCPResourceStore[*v2.CiliumBGPAdvertisement]()
	serviceStore := store.NewFakeDiffStore[*slim_corev1.Service]()
	epStore := store.NewFakeDiffStore[*k8s.Endpoints]()

	params := ServiceReconcilerIn{
		Logger: serviceReconcilerTestLogger,
		PeerAdvert: NewCiliumPeerAdvertisement(
			PeerAdvertisementIn{
				Logger:          podCIDRTestLogger,
				PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](peerConfigs),
				AdvertStore:     advertStore,
			}),
		SvcDiffStore: serviceStore,
		EPDiffStore:  epStore,
	}

	svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
	testBGPInstance := instance.NewFakeBGPInstance()
	svcReconciler.Init(testBGPInstance)
	defer svcReconciler.Cleanup(testBGPInstance)

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

		// validate that advertised paths match expected metadata
		advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

		// validate that advertised policies match expected attributes
		advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.expectedMetadata.ServiceRoutePolicies)
	}
}

func Test_ServiceVIPSharing(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	peerConfigs := []*v2.CiliumBGPPeerConfig{redPeerConfig}

	steps := []struct {
		name             string
		upsertAdverts    []*v2.CiliumBGPAdvertisement
		upsertServices   []*slim_corev1.Service
		deletetServices  []*slim_corev1.Service
		upsertEPs        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name: "Add service 1 (LoadBalancer) with advertisement",
			upsertAdverts: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v2.BGPAdvertisement{
					AdvertisementType: v2.BGPServiceAdvert,
					Service: &v2.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			upsertServices: []*slim_corev1.Service{redLBSvc},
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
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Add service 2 (LoadBalancer) with the same VIP",
			upsertServices: []*slim_corev1.Service{redLBSvc2()},
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
					redSvc2Key: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
					redSvc2Key: RoutePolicyMap{
						redPeer65001Svc2v4LBRPName: redPeer65001Svc2v4LBRP(),
						redPeer65001Svc2v6LBRPName: redPeer65001Svc2v6LBRP(),
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "Delete service 1",
			deletetServices: []*slim_corev1.Service{redLBSvc},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvc2Key: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvc2Key: RoutePolicyMap{
						redPeer65001Svc2v4LBRPName: redPeer65001Svc2v4LBRP(),
						redPeer65001Svc2v6LBRPName: redPeer65001Svc2v6LBRP(),
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "Delete service 2",
			deletetServices: []*slim_corev1.Service{redLBSvc2()},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							{
								AdvertisementType: v2.BGPServiceAdvert,
								Service: &v2.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Add service 1 (LoadBalancer) with overlapping advertisement",
			upsertAdverts: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(
					lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
					lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
				),
			},
			upsertServices: []*slim_corev1.Service{redLBSvc},
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
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRP.Name,
							Type: redPeer65001v4LBRP.Type,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: redPeer65001v4LBRP.Statements[0].Conditions,
									Actions: types.RoutePolicyActions{
										RouteAction:         types.RoutePolicyActionAccept,
										AddCommunities:      []string{"101:101", "202:202", "no-export"},
										AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222"},
										SetLocalPreference:  &localPrefHigh,
									},
								},
							},
						},
						redPeer65001v6LBRPName: &types.RoutePolicy{
							Name: redPeer65001v6LBRP.Name,
							Type: redPeer65001v6LBRP.Type,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: redPeer65001v6LBRP.Statements[0].Conditions,
									Actions: types.RoutePolicyActions{
										RouteAction:         types.RoutePolicyActionAccept,
										AddCommunities:      []string{"101:101", "202:202", "no-export"},
										AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222"},
										SetLocalPreference:  &localPrefHigh,
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					"red-peer-65001": PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
							lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
							lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
						},
					},
				},
			},
		},
	}

	req := require.New(t)
	advertStore := store.NewMockBGPCPResourceStore[*v2.CiliumBGPAdvertisement]()
	serviceStore := store.NewFakeDiffStore[*slim_corev1.Service]()
	epStore := store.NewFakeDiffStore[*k8s.Endpoints]()

	params := ServiceReconcilerIn{
		Logger: serviceReconcilerTestLogger,
		PeerAdvert: NewCiliumPeerAdvertisement(
			PeerAdvertisementIn{
				Logger:          podCIDRTestLogger,
				PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](peerConfigs),
				AdvertStore:     advertStore,
			}),
		SvcDiffStore: serviceStore,
		EPDiffStore:  epStore,
	}

	svcReconciler := NewServiceReconciler(params).Reconciler.(*ServiceReconciler)
	testBGPInstance := instance.NewFakeBGPInstance()
	svcReconciler.Init(testBGPInstance)
	defer svcReconciler.Cleanup(testBGPInstance)

	for _, tt := range steps {
		t.Logf("Running step - %s", tt.name)
		for _, advert := range tt.upsertAdverts {
			advertStore.Upsert(advert)
		}

		for _, svc := range tt.upsertServices {
			serviceStore.Upsert(svc)
		}

		for _, svc := range tt.deletetServices {
			serviceStore.Delete(resource.Key{Name: svc.Name, Namespace: svc.Namespace})
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

		// validate that advertised paths match expected metadata
		advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

		// validate that advertised policies match expected attributes
		advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.expectedMetadata.ServiceRoutePolicies)
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

	req.Equalf(expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies,
		"ServiceRoutePolicies mismatch, expected: %v, got: %v", expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies)
}

func advertisedPrefixesMatch(req *require.Assertions, bgpInstance *instance.BGPInstance, expectedPaths ResourceAFPathsMap) {
	expected := make(map[string]*types.Path)
	for _, svcPaths := range expectedPaths {
		for _, afPaths := range svcPaths {
			for _, path := range afPaths {
				expected[path.NLRI.String()] = path
			}
		}
	}

	advertised := make(map[string]*types.Path)
	routes, err := bgpInstance.Router.GetRoutes(context.Background(), &types.GetRoutesRequest{TableType: types.TableTypeLocRIB})
	req.NoError(err)
	for _, route := range routes.Routes {
		for _, path := range route.Paths {
			advertised[path.NLRI.String()] = path
		}
	}

	expPrefixes := slices.Collect(maps.Keys(expected))
	advPrefixes := slices.Collect(maps.Keys(advertised))
	req.ElementsMatchf(expPrefixes, advPrefixes, "advertised prefixes do not match expected metadata, expected: %v, got: %v", expPrefixes, advPrefixes)
}

// advertisedPoliciesAttributesMatch checks that the policies expected were in fact configured on the internal BGP speaker
func advertisedPoliciesAttributesMatch(
	req *require.Assertions,
	bgpInstance *instance.BGPInstance,
	expectedResourceRoutePolicyMap ResourceRoutePolicyMap,
) {
	response, err := bgpInstance.Router.GetRoutePolicies(context.Background())
	req.NoError(err)

	// Index policies by name
	expectedPolicies := make(map[string]*types.RoutePolicy)
	for _, routePolicyMap := range expectedResourceRoutePolicyMap {
		for policyName, policy := range routePolicyMap {
			expectedPolicies[policyName] = policy
		}
	}

	req.Len(response.Policies, len(expectedPolicies))
	for _, policy := range response.Policies {
		req.Equal(policy, expectedPolicies[policy.Name])
	}
}
