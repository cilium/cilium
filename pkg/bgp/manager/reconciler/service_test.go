// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/option"
	"github.com/cilium/cilium/pkg/bgp/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	ciliumoption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
)

// svcTestStep represents one step in the service reconciler test execution.
// Each step builds on the state of the previous step: if some of the step resources is provided,
// the resource is upserted (in case of the "delete" prefix, it is deleted).
type svcTestStep struct {
	name             string
	peers            []v2.CiliumBGPNodePeer
	peerConfigs      []*v2.CiliumBGPPeerConfig
	advertisements   []*v2.CiliumBGPAdvertisement
	frontends        []*loadbalancer.Frontend
	deleteFrontends  []*loadbalancer.Frontend
	backends         []*loadbalancer.Backend
	expectedMetadata ServiceReconcilerMetadata
}

type svcTestFixture struct {
	hive            *ciliumhive.Hive
	svcReconciler   *ServiceReconciler
	db              *statedb.DB
	frontends       statedb.RWTable[*loadbalancer.Frontend]
	PeerConfigStore *store.MockBGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	AdvertStore     *store.MockBGPCPResourceStore[*v2.CiliumBGPAdvertisement]
}

type svcTestAggregation struct {
	aggregationLengthIPv4 int16
	aggregationLengthIPv6 int16
}

var (
	redSvcKey            = resource.Key{Name: "red-svc", Namespace: "non-default"}
	redSvc2Key           = resource.Key{Name: "red-svc2", Namespace: "non-default"}
	redSvcSelector       = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	mismatchSvcSelector  = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	ingressV4            = "192.168.0.1"
	ingressV4Prefix      = "192.168.0.1/32"
	ingressV4PrefixAggr  = "192.168.0.0/24"
	externalV4           = "192.168.0.2"
	externalV4Prefix     = "192.168.0.2/32"
	externalV4PrefixAggr = "192.168.0.0/24"
	clusterV4            = "192.168.0.3"
	clusterV4Prefix      = "192.168.0.3/32"
	clusterV4PrefixAggr  = "192.168.0.0/24"
	ingressV6            = "2001:db8::1"
	ingressV6Prefix      = "2001:db8::1/128"
	ingressV6PrefixAggr  = "2001:db8::/120"
	externalV6           = "2001:db8::2"
	externalV6Prefix     = "2001:db8::2/128"
	externalV6PrefixAggr = "2001:db8::/120"
	clusterV6            = "2001:db8::3"
	clusterV6Prefix      = "2001:db8::3/128"
	clusterV6PrefixAggr  = "2001:db8::/120"
	aggregation          = svcTestAggregation{aggregationLengthIPv4: 24, aggregationLengthIPv6: 120}

	redSvcName      = loadbalancer.NewServiceName(redSvcKey.Namespace, redSvcKey.Name)
	redSvc2Name     = loadbalancer.NewServiceName(redSvc2Key.Namespace, redSvc2Key.Name)
	redSvcLabels    = labels.Map2Labels(redSvcSelector.MatchLabels, string(source.Kubernetes))
	redSvcTPCluster = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	redSvcTPLocal = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}
	redSvcExtTPLocal = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	redSvcIntTPLocal = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
	}
	// redSvcExtTPLocalWithProxy is a service with eTP=Local and ProxyRedirect set,
	// simulating a Gateway API / Ingress service where local Envoy handles traffic.
	redSvcExtTPLocalWithProxy = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		ProxyRedirect: &loadbalancer.ProxyRedirect{
			ProxyPort: 10000,
			Ports:     []uint16{80, 443},
		},
	}
	redSvc2TPCluster = &loadbalancer.Service{
		Name:             redSvc2Name,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	svcFrontend = func(svc *loadbalancer.Service, addr string, port uint16, svcType loadbalancer.SVCType) *loadbalancer.Frontend {
		return &loadbalancer.Frontend{
			FrontendParams: loadbalancer.FrontendParams{
				ServiceName: svc.Name,
				Address:     loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster(addr), port, 0),
				Type:        svcType,
			},
			Service:  svc,
			Backends: func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {},
		}
	}
	svcLBFrontend = func(svc *loadbalancer.Service, addr string) *loadbalancer.Frontend {
		return svcFrontend(svc, addr, 80, loadbalancer.SVCTypeLoadBalancer)
	}
	svcExtIPFrontend = func(svc *loadbalancer.Service, addr string) *loadbalancer.Frontend {
		return svcFrontend(svc, addr, 80, loadbalancer.SVCTypeExternalIPs)
	}
	svcClusterIPFrontend = func(svc *loadbalancer.Service, addr string) *loadbalancer.Frontend {
		return svcFrontend(svc, addr, 80, loadbalancer.SVCTypeClusterIP)
	}
	backendAddr = func(addr string, port uint16) loadbalancer.L3n4Addr {
		return loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			cmtypes.MustParseAddrCluster(addr),
			port,
			loadbalancer.ScopeExternal,
		)
	}
	redSvcBackendsLocal = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateActive),
	}
	redSvcBackendsMixed = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("10.2.0.1", 80), "node2", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:2000::1", 80), "node2", loadbalancer.BackendStateActive),
	}
	redSvcBackendsRemote = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.2.0.1", 80), "node2", loadbalancer.BackendStateActive),
		newTestBackend(redSvcName, backendAddr("2001:db8:2000::1", 80), "node2", loadbalancer.BackendStateActive),
	}
	redSvcBackendsLocalTerminating = []*loadbalancer.Backend{
		newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateTerminating),
		newTestBackend(redSvcName, backendAddr("2001:db8:1000::1", 80), "node1", loadbalancer.BackendStateTerminating),
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
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
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
	redPeer65001v4LBRPAggr = &types.RoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV4PrefixAggr),
								PrefixLenMin: 24,
								PrefixLenMax: 24,
							},
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
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
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
	redPeer65001v6LBRPAggr = &types.RoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(ingressV6PrefixAggr),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
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

	redPeer65001v4ExtRPName = PolicyName("red-peer-65001", "ipv4", v2.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v4ExtRP     = &types.RoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
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
	redPeer65001v4ExtRPAggr = &types.RoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV4PrefixAggr),
								PrefixLenMin: 24,
								PrefixLenMax: 24,
							},
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
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
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
	redPeer65001v6ExtRPAggr = &types.RoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(externalV6PrefixAggr),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
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

	redPeer65001v4ClusterRPName = PolicyName("red-peer-65001", "ipv4", v2.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v4ClusterRP     = &types.RoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV4Prefix),
								PrefixLenMin: 32,
								PrefixLenMax: 32,
							},
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
	redPeer65001v4ClusterRPAggr = &types.RoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV4PrefixAggr),
								PrefixLenMin: 24,
								PrefixLenMax: 24,
							},
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
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV6Prefix),
								PrefixLenMin: 128,
								PrefixLenMax: 128,
							},
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
	redPeer65001v6ClusterRPAggr = &types.RoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: &types.RoutePolicyNeighborMatch{
						Type:      types.RoutePolicyMatchAny,
						Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					},
					MatchPrefixes: &types.RoutePolicyPrefixMatch{
						Type: types.RoutePolicyMatchAny,
						Prefixes: []types.RoutePolicyPrefix{
							{
								CIDR:         netip.MustParsePrefix(clusterV6PrefixAggr),
								PrefixLenMin: 120,
								PrefixLenMax: 120,
							},
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
			Addresses:             []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
			AggregationLengthIPv4: nil,
			AggregationLengthIPv6: nil,
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	lbSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector, aggregation ...svcTestAggregation) v2.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		if len(aggregation) != 0 {
			cp.Service.AggregationLengthIPv4 = &aggregation[0].aggregationLengthIPv4
			cp.Service.AggregationLengthIPv6 = &aggregation[0].aggregationLengthIPv6
		}
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

	externalSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector, aggregation ...svcTestAggregation) v2.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		if len(aggregation) != 0 {
			cp.Service.AggregationLengthIPv4 = &aggregation[0].aggregationLengthIPv4
			cp.Service.AggregationLengthIPv6 = &aggregation[0].aggregationLengthIPv6
		}
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

	clusterIPSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector, aggregation ...svcTestAggregation) v2.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		if len(aggregation) != 0 {
			cp.Service.AggregationLengthIPv4 = &aggregation[0].aggregationLengthIPv4
			cp.Service.AggregationLengthIPv6 = &aggregation[0].aggregationLengthIPv6
		}
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

	testPeerID = PeerID{
		Name:    "red-peer-65001",
		Address: "10.10.10.1",
	}

	bgpConfig = func() option.BGPConfig {
		config := option.DefaultConfig
		return config
	}

	bgpConfigWithLegacyOriginAttrEnabled = func() option.BGPConfig {
		config := option.DefaultConfig
		config.EnableBGPLegacyOriginAttribute = true
		return config
	}
)

// Test_ServiceLBReconciler tests reconciliation of service of type load-balancer
func Test_ServiceLBReconciler(t *testing.T) {
	runServiceTests(t, bgpConfig(), []svcTestStep{
		{
			name:           "Service (LB) with advertisement( empty )",
			peerConfigs:    []*v2.CiliumBGPPeerConfig{redPeerConfig},
			frontends:      []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:      "Service (LB) with advertisement(LB) - mismatch labels",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=cluster)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (LB) with advertisement(LB) and routes aggregation - matching labels (eTP=cluster, iTP=local)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcIntTPLocal, ingressV4), svcLBFrontend(redSvcIntTPLocal, ingressV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector, aggregation)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4PrefixAggr: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6PrefixAggr: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6PrefixAggr)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRPAggr,
						redPeer65001v6LBRPName: redPeer65001v6LBRPAggr,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
					},
				},
			},
		},
		{
			name:      "Service (LB) with advertisement(LB) and routes aggregation - matching labels (eTP=local, iTP=cluster - no aggregation)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsLocal,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector, aggregation)),
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
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
					},
				},
			},
		},
		{
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on node)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsLocal,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=local, mixed ep)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsMixed,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on remote)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsRemote,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=local, backends are terminating)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsLocalTerminating,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
		// Test that Gateway API / Ingress services with ProxyRedirect are advertised
		// even with eTP=Local and no local backends, because traffic is handled by
		// the local Envoy proxy.
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, no backends, ProxyRedirect set)",
			peerConfigs: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocalWithProxy, ingressV4), svcLBFrontend(redSvcExtTPLocalWithProxy, ingressV6)},
			backends:    nil, // no backends
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
					testPeerID: PeerFamilyAdvertisements{
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
	})
}

func Test_ServiceLBReconcilerWithLegacyOriginAttr(t *testing.T) {
	runServiceTests(t, bgpConfigWithLegacyOriginAttrEnabled(), []svcTestStep{
		{
			name:        "Service (LB) with advertisement(LB) and legacy origin attr - matching labels (eTP=cluster)",
			peerConfigs: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			frontends:   []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.SetPathOriginAttrIncomplete(types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix))),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.SetPathOriginAttrIncomplete(types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix))),
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
					testPeerID: PeerFamilyAdvertisements{
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
	})
}

// Test_ServiceExternalIPReconciler tests reconciliation of cluster service with external IP
func Test_ServiceExternalIPReconciler(t *testing.T) {
	runServiceTests(t, bgpConfig(), []svcTestStep{
		{
			name:           "Service (External) with advertisement( empty )",
			peerConfigs:    []*v2.CiliumBGPPeerConfig{redPeerConfig},
			frontends:      []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:      "Service (External) with advertisement(External) - mismatch labels",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (External) with advertisement(External) - matching labels (eTP=cluster)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (External) with advertisement(External) and routes aggregation - matching labels (eTP=cluster, iTP=local)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcIntTPLocal, externalV4), svcExtIPFrontend(redSvcIntTPLocal, externalV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector, aggregation)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4PrefixAggr: types.NewPathForPrefix(netip.MustParsePrefix(externalV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6PrefixAggr: types.NewPathForPrefix(netip.MustParsePrefix(externalV6PrefixAggr)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRPAggr,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRPAggr,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
					},
				},
			},
		},
		{
			name:      "Service (External) with advertisement(External) and routes aggregation - matching labels (eTP=local, iTP=cluster - no aggregation)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:  redSvcBackendsLocal,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector, aggregation)),
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
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
					},
				},
			},
		},
		{
			name:      "Service (External) with advertisement(External) - matching labels (eTP=local, ep on node)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:  redSvcBackendsLocal,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (External) with advertisement(External) - matching labels (eTP=local, mixed ep)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:  redSvcBackendsMixed,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (External) with advertisement(External) - matching labels (eTP=local, ep on remote)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:  redSvcBackendsRemote,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (External) with overlapping advertisement(External) - matching labels (eTP=cluster)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
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
					testPeerID: PeerFamilyAdvertisements{
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
	})
}

// Test_ServiceClusterIPReconciler tests reconciliation of cluster service
func Test_ServiceClusterIPReconciler(t *testing.T) {
	runServiceTests(t, bgpConfig(), []svcTestStep{
		{
			name:           "Service (Cluster) with advertisement( empty )",
			peerConfigs:    []*v2.CiliumBGPPeerConfig{redPeerConfig},
			frontends:      []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:      "Service (Cluster) with advertisement(Cluster) - mismatch labels",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=cluster)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (Cluster) with advertisement(Cluster) and routes aggregation - matching labels (iTP=cluster)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector, aggregation)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4PrefixAggr: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6PrefixAggr: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6PrefixAggr)),
						},
					},
				},
				ServiceRoutePolicies: ResourceRoutePolicyMap{
					redSvcKey: RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRPAggr,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRPAggr,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
					},
				},
			},
		},
		{
			name:      "Service (Cluster) with advertisement(Cluster) and routes aggregation - matching labels (iTP=local - no aggregation)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:  redSvcBackendsLocal,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector, aggregation)),
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
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector, aggregation),
						},
					},
				},
			},
		},
		{
			name:      "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=local, ep on node)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:  redSvcBackendsLocal,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=local, mixed ep)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:  redSvcBackendsMixed,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=local, ep on remote)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:  redSvcBackendsRemote,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name:      "Service (Cluster) with overlapping advertisement(Cluster) - matching labels (iTP=cluster)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
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
					testPeerID: PeerFamilyAdvertisements{
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
	})
}

// Test_ServiceAndAdvertisementModifications is a step test, in which each step modifies the advertisement or service parameters.
func Test_ServiceAndAdvertisementModifications(t *testing.T) {
	runServiceTests(t, bgpConfig(), []svcTestStep{
		{
			name:           "Initial setup - Service (nil) with advertisement( empty )",
			peerConfigs:    []*v2.CiliumBGPPeerConfig{redPeerConfig},
			advertisements: nil,
			frontends:      nil,
			backends:       nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name: "Add service (Cluster, External) with advertisement(Cluster) - matching labels",
			advertisements: []*v2.CiliumBGPAdvertisement{
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
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6),
				svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6),
			},
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
					testPeerID: PeerFamilyAdvertisements{
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
			advertisements: []*v2.CiliumBGPAdvertisement{
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
					testPeerID: PeerFamilyAdvertisements{
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
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPLocal, clusterV4), svcClusterIPFrontend(redSvcTPLocal, clusterV6),
				svcExtIPFrontend(redSvcTPLocal, externalV4), svcExtIPFrontend(redSvcTPLocal, externalV6),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn, since traffic policy is local and there are no endpoints.
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name: "Update local endpoints (Cluster, External)",
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPLocal, clusterV4), svcClusterIPFrontend(redSvcTPLocal, clusterV6),
				svcExtIPFrontend(redSvcTPLocal, externalV4), svcExtIPFrontend(redSvcTPLocal, externalV6),
			},
			backends: redSvcBackendsLocal,
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
					testPeerID: PeerFamilyAdvertisements{
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
			name: "Delete local endpoints (Cluster, External)",
			frontends: []*loadbalancer.Frontend{
				svcClusterIPFrontend(redSvcTPLocal, clusterV4), svcClusterIPFrontend(redSvcTPLocal, clusterV6),
				svcExtIPFrontend(redSvcTPLocal, externalV4), svcExtIPFrontend(redSvcTPLocal, externalV6),
			},
			backends: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn since local endpoints were deleted.
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
	})
}

func Test_ServiceVIPSharing(t *testing.T) {
	runServiceTests(t, bgpConfig(), []svcTestStep{
		{
			name:        "Add service 1 (LoadBalancer, port 80) with advertisement",
			peerConfigs: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcTPCluster, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcTPCluster, ingressV6, 80, loadbalancer.SVCTypeLoadBalancer),
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
					testPeerID: PeerFamilyAdvertisements{
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
			name: "Add service 2 (LoadBalancer, port 443) with the same VIP",
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvc2TPCluster, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvc2TPCluster, ingressV6, 443, loadbalancer.SVCTypeLoadBalancer),
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
					testPeerID: PeerFamilyAdvertisements{
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
			name: "Delete service 1 (LoadBalancer, port 80)",
			deleteFrontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcTPCluster, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcTPCluster, ingressV6, 80, loadbalancer.SVCTypeLoadBalancer),
			},
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
					testPeerID: PeerFamilyAdvertisements{
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
			name: "Delete service 2 (LoadBalancer, port 443)",
			deleteFrontends: []*loadbalancer.Frontend{
				svcFrontend(redSvc2TPCluster, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvc2TPCluster, ingressV6, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         ResourceAFPathsMap{},
				ServiceRoutePolicies: ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
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
			name: "Add service 1 (LoadBalancer, port 80) with overlapping advertisement",
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(
					lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes),
					lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2),
				),
			},
			frontends: []*loadbalancer.Frontend{
				svcFrontend(redSvcTPCluster, ingressV4, 80, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvcTPCluster, ingressV6, 80, loadbalancer.SVCTypeLoadBalancer),
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
					testPeerID: PeerFamilyAdvertisements{
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
	})
}

func Test_ServiceAdvertisementWithPeerIPChange(t *testing.T) {
	runServiceTests(t, bgpConfig(), []svcTestStep{
		{
			name:        "Add service and advertisement",
			peerConfigs: []*v2.CiliumBGPPeerConfig{redPeerConfig},
			peers: []v2.CiliumBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v2.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
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
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
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
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV4Prefix),
													PrefixLenMin: 32,
													PrefixLenMax: 32,
												},
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
						redPeer65001v6LBRPName: &types.RoutePolicy{
							Name: redPeer65001v6LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV6Prefix),
													PrefixLenMin: 128,
													PrefixLenMax: 128,
												},
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					PeerID{Name: "red-peer-65001", Address: "10.10.10.1"}: PeerFamilyAdvertisements{
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
			name: "Change peer IP address",
			peers: []v2.CiliumBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.99"),
					PeerConfigRef: &v2.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
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
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.99")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV4Prefix),
													PrefixLenMin: 32,
													PrefixLenMax: 32,
												},
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
						redPeer65001v6LBRPName: &types.RoutePolicy{
							Name: redPeer65001v6LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: &types.RoutePolicyNeighborMatch{
											Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.99")},
										},
										MatchPrefixes: &types.RoutePolicyPrefixMatch{
											Type: types.RoutePolicyMatchAny,
											Prefixes: []types.RoutePolicyPrefix{
												{
													CIDR:         netip.MustParsePrefix(ingressV6Prefix),
													PrefixLenMin: 128,
													PrefixLenMax: 128,
												},
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					PeerID{Name: "red-peer-65001", Address: "10.10.10.99"}: PeerFamilyAdvertisements{
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
	})
}

func runServiceTests(t *testing.T, config option.BGPConfig, steps []svcTestStep) {
	// start the test hive
	f := newServiceTestFixture(t, config)
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	// init BGP instance
	testBGPInstance := instance.NewFakeBGPInstance()
	f.svcReconciler.Init(testBGPInstance)
	t.Cleanup(func() {
		f.svcReconciler.Cleanup(testBGPInstance)
	})

	for _, tt := range steps {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			// upsert peeConfigs & advertisements
			for _, peerConfig := range tt.peerConfigs {
				f.PeerConfigStore.Upsert(peerConfig)
			}
			for _, advert := range tt.advertisements {
				f.AdvertStore.Upsert(advert)
			}

			// upsert / delete service frontends & backends
			tx := f.db.WriteTxn(f.frontends)
			// delete frontends
			for _, fe := range tt.deleteFrontends {
				_, _, err = f.frontends.Delete(tx, fe)
				req.NoError(err)
			}
			// upsert frontends with backends
			nextBackendRevision := statedb.Revision(1)
			for _, fe := range tt.frontends {
				// set frontend's backends
				for _, be := range tt.backends {
					if fe.Address.IsIPv6() == be.Address.IsIPv6() && fe.Address.Port() == be.Address.Port() {
						fe.Backends = concatBackend(fe.Backends, *be.GetInstance(fe.Service.Name), nextBackendRevision)
						nextBackendRevision++
					}
				}
				_, _, err = f.frontends.Insert(tx, fe)
				req.NoError(err)
			}
			tx.Commit()

			desiredConfig := testBGPInstanceConfig
			if len(tt.peers) > 0 {
				// set updatePeers in the node instance
				desiredConfig = testBGPInstanceConfig.DeepCopy()
				desiredConfig.Peers = tt.peers
			}

			// reconcile twice to validate idempotency
			for range 2 {
				err := f.svcReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: desiredConfig,
					CiliumNode:    testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, f.svcReconciler.getMetadata(testBGPInstance))

			// validate that advertised paths match expected metadata
			advertisedPrefixesAndPathAttrMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

			// validate that advertised policies match expected attributes
			advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.expectedMetadata.ServiceRoutePolicies)
		})
	}
}

func newServiceTestFixture(t *testing.T, config option.BGPConfig) *svcTestFixture {
	f := &svcTestFixture{
		PeerConfigStore: store.NewMockBGPCPResourceStore[*v2.CiliumBGPPeerConfig](),
		AdvertStore:     store.NewMockBGPCPResourceStore[*v2.CiliumBGPAdvertisement](),
	}
	f.hive = ciliumhive.New(
		cell.Module("service-reconciler-test", "Service reconciler test",
			cell.Provide(
				signaler.NewBGPCPSignaler,

				loadbalancer.NewFrontendsTable,
				statedb.RWTable[*loadbalancer.Frontend].ToTable,

				func() *CiliumPeerAdvertisement {
					return NewCiliumPeerAdvertisement(
						PeerAdvertisementIn{
							Logger:          hivetest.Logger(t),
							PeerConfigStore: f.PeerConfigStore,
							AdvertStore:     f.AdvertStore,
						})
				},
				func() *ciliumoption.DaemonConfig {
					return &ciliumoption.DaemonConfig{
						EnableBGPControlPlane: true,
					}
				},
				func() option.BGPConfig {
					return config
				},
				func() loadbalancer.Config {
					return loadbalancer.Config{}
				},
			),
			svcrouteconfig.Cell,
			cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*loadbalancer.Frontend]) {
				f.db = db
				f.frontends = table
			}),
			cell.Invoke(func(p ServiceReconcilerIn) {
				out := NewServiceReconciler(p)
				f.svcReconciler = out.Reconciler.(*ServiceReconciler)
			}),
		),
	)
	return f
}

func newTestBackend(svcName loadbalancer.ServiceName, addr loadbalancer.L3n4Addr, node string, state loadbalancer.BackendState) *loadbalancer.Backend {
	part.RegisterKeyType(loadbalancer.BackendInstanceKey.Key)
	be := &loadbalancer.Backend{
		Address:   addr,
		Instances: part.Map[loadbalancer.BackendInstanceKey, loadbalancer.BackendParams]{},
	}
	be.Instances = be.Instances.Set(
		loadbalancer.BackendInstanceKey{ServiceName: svcName, SourcePriority: 0},
		loadbalancer.BackendParams{
			Address:   addr,
			NodeName:  node,
			PortNames: nil,
			Weight:    0,
			State:     state,
		},
	)
	return be
}

func concatBackend(bes loadbalancer.BackendsSeq2, be loadbalancer.BackendParams, rev statedb.Revision) loadbalancer.BackendsSeq2 {
	return func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {
		if !yield(be, rev) {
			return
		}
		bes(yield)
	}
}

func serviceMetadataEqual(req *require.Assertions, expectedMetadata, runningMetadata ServiceReconcilerMetadata) {
	req.Truef(PeerAdvertisementsEqual(expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements),
		"ServiceAdvertisements mismatch, expected: %v, got: %v", expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements)

	req.Lenf(runningMetadata.ServicePaths, len(expectedMetadata.ServicePaths),
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

func advertisedPrefixesAndPathAttrMatch(req *require.Assertions, bgpInstance *instance.BGPInstance, expectedPaths ResourceAFPathsMap) {
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

	for _, advPrefix := range advPrefixes {
		req.ElementsMatch(expected[advPrefix].PathAttributes, advertised[advPrefix].PathAttributes, "advertised prefixes do not match expected path attributes, expected: %v, got: %v", expected[advPrefix].PathAttributes, advertised[advPrefix].PathAttributes)
	}
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
		maps.Copy(expectedPolicies, routePolicyMap)
	}

	req.Len(response.Policies, len(expectedPolicies))
	for _, policy := range response.Policies {
		req.Equal(policy, expectedPolicies[policy.Name])
	}
}
