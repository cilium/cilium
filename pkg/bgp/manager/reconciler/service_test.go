// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
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
	name                  string
	peers                 []v2.CiliumBGPNodePeer
	peerConfigs           []*v2.CiliumBGPPeerConfig
	advertisements        []*v2.CiliumBGPAdvertisement
	frontends             []*loadbalancer.Frontend
	deleteFrontends       []*loadbalancer.Frontend
	backends              []*loadbalancer.Backend
	expectedMetadata      ServiceReconcilerMetadata
	ExpectedRoutePolicies []*bgpTables.DesiredRoutePolicy
}
type svcTestFixture struct {
	hive                  *ciliumhive.Hive
	svcReconciler         *ServiceReconciler
	routePolicyReconciler *RoutePolicyReconciler
	db                    *statedb.DB
	frontends             statedb.RWTable[*loadbalancer.Frontend]
	PeerConfigStore       *store.MockBGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	AdvertStore           *store.MockBGPCPResourceStore[*v2.CiliumBGPAdvertisement]
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
	// redSvcExtTPLocalWithProxy is a service with eTP=Local and ProxyRedirects set,
	// simulating a Gateway API / Ingress service where local Envoy handles traffic.
	redSvcExtTPLocalWithProxy = &loadbalancer.Service{
		Name:             redSvcName,
		Labels:           redSvcLabels,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		ProxyRedirects: loadbalancer.ProxyRedirects{{
			ProxyPort: 10000,
			Ports:     []uint16{80, 443},
		}},
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
			Backends: func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {},
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

	redPeer65001v4LBRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v4LBRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4LBRPName + "-ipv4",
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
	}
	redPeer65001v4LBRPAggr = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority + 1,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4LBRPName + "-ipv4-agg-24",
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
	}
	redPeer65001Svc2v4LBRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v4LBRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvc2Key,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001Svc2v4LBRPName + "-ipv4",
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
	}

	redPeer65001v6LBRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v6LBRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6LBRPName + "-ipv6",
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
	}
	redPeer65001v6LBRPAggr = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority + 1,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6LBRPName + "-ipv6-agg-120",
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
	}
	redPeer65001Svc2v6LBRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v6LBRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvc2Key,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001Svc2v6LBRPName + "-ipv6",
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
	}

	redPeer65001v4ExtRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v4ExtRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4ExtRPName + "-ipv4",
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
	}
	redPeer65001v4ExtRPAggr = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority + 1,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4ExtRPName + "-ipv4-agg-24",
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
	}

	redPeer65001v6ExtRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v6ExtRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6ExtRPName + "-ipv6",
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
	}
	redPeer65001v6ExtRPAggr = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority + 1,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6ExtRPName + "-ipv6-agg-120",
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
	}

	redPeer65001v4ClusterRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v4ClusterRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4ClusterRPName + "-ipv4",
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
	}
	redPeer65001v4ClusterRPAggr = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority + 1,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4ClusterRPName + "-ipv4-agg-24",
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
	}

	redPeer65001v6ClusterRPName = PolicyStatementName(v2.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v6ClusterRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6ClusterRPName + "-ipv6",
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
	}
	redPeer65001v6ClusterRPAggr = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       "red-peer-65001",
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   ServiceReconcilerPriority + 1,
		Owner:      ServiceReconcilerName,
		Resource:   redSvcKey,
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6ClusterRPName + "-ipv6-agg-120",
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

	lbSvcAdvertWithSelectorAttributes = func(selector *slim_metav1.LabelSelector, attributes *v2.BGPAttributes, aggregation ...svcTestAggregation) v2.BGPAdvertisement {
		cp := lbSvcAdvertWithSelector(selector, aggregation...)
		cp.Attributes = attributes
		return cp
	}

	exactAdvert           = lbSvcAdvertWithSelector(redSvcSelector)
	aggregatedAdvert      = lbSvcAdvertWithSelector(redSvcSelector, aggregation)
	aggregatedAdvertHigh  = lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes, aggregation)
	aggregatedAdvertLow   = lbSvcAdvertWithSelectorAttributes(redSvcSelector, redPeer65001BgpAttributes2, aggregation)
	mergedAggregatePolicy = func(policy *bgpTables.DesiredRoutePolicy) *bgpTables.DesiredRoutePolicy {
		mergedPolicy := *policy
		mergedStatement := *policy.Statement
		mergedStatement.Actions = types.RoutePolicyActions{
			RouteAction:         types.RoutePolicyActionAccept,
			AddCommunities:      []string{"101:101", "202:202", "no-export"},
			AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222"},
			SetLocalPreference:  &localPrefHigh,
		}
		mergedPolicy.Statement = &mergedStatement
		return &mergedPolicy
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
				ServicePaths: ResourceAFPathsMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
			ExpectedRoutePolicies: nil,
		},
		{
			name:      "Service (LB) with advertisement(LB) - mismatch labels",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
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
							ingressV4PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6PrefixAggr)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRPAggr, redPeer65001v6LBRPAggr},
		},
		{
			name:      "Service (LB) with exact and aggregated advertisements",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcTPCluster, ingressV4), svcLBFrontend(redSvcTPCluster, ingressV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exactAdvert, aggregatedAdvert),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix:     types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
							ingressV4PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix:     types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
							ingressV6PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6PrefixAggr)),
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{exactAdvert, aggregatedAdvert},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{exactAdvert, aggregatedAdvert},
					},
				},
			},
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4LBRP,
				redPeer65001v6LBRP,
				redPeer65001v4LBRPAggr,
				redPeer65001v6LBRPAggr,
			},
		},
		{
			name: "Service (LB) with two aggregated advertisements with different attributes",
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(aggregatedAdvertHigh, aggregatedAdvertLow),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{
					redSvcKey: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6PrefixAggr)),
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v2.BGPAdvertisement{aggregatedAdvertHigh, aggregatedAdvertLow},
						{Afi: "ipv6", Safi: "unicast"}: []v2.BGPAdvertisement{aggregatedAdvertHigh, aggregatedAdvertLow},
					},
				},
			},
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				mergedAggregatePolicy(redPeer65001v4LBRPAggr),
				mergedAggregatePolicy(redPeer65001v6LBRPAggr),
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
		},
		{
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on remote)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsRemote,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
		},
		{
			name:      "Service (LB) with advertisement(LB) - matching labels (eTP=local, backends are terminating)",
			frontends: []*loadbalancer.Frontend{svcLBFrontend(redSvcExtTPLocal, ingressV4), svcLBFrontend(redSvcExtTPLocal, ingressV6)},
			backends:  redSvcBackendsLocalTerminating,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
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
							ingressV4Prefix: types.SetPathOriginAttrIncomplete(types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix))),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.SetPathOriginAttrIncomplete(types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix))),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
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
				ServicePaths: ResourceAFPathsMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
			ExpectedRoutePolicies: nil,
		},
		{
			name:      "Service (External) with advertisement(External) - mismatch labels",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcTPCluster, externalV4), svcExtIPFrontend(redSvcTPCluster, externalV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ExtRP, redPeer65001v6ExtRP},
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
							externalV4PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6PrefixAggr)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ExtRPAggr, redPeer65001v6ExtRPAggr},
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
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ExtRP, redPeer65001v6ExtRP},
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
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ExtRP, redPeer65001v6ExtRP},
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
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ExtRP, redPeer65001v6ExtRP},
		},
		{
			name:      "Service (External) with advertisement(External) - matching labels (eTP=local, ep on remote)",
			frontends: []*loadbalancer.Frontend{svcExtIPFrontend(redSvcExtTPLocal, externalV4), svcExtIPFrontend(redSvcExtTPLocal, externalV6)},
			backends:  redSvcBackendsRemote,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name:       redPeer65001v4ExtRPName + "-ipv4",
						Conditions: redPeer65001v4ExtRP.Statement.Conditions,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddCommunities:      []string{"101:101", "202:202", "303:303", "no-export"},
							AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222", "3333:3333:3333"},
							SetLocalPreference:  &localPrefHigh,
						},
					},
				},
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name:       redPeer65001v6ExtRPName + "-ipv6",
						Conditions: redPeer65001v6ExtRP.Statement.Conditions,
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
				ServicePaths: ResourceAFPathsMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
			ExpectedRoutePolicies: nil,
		},
		{
			name:      "Service (Cluster) with advertisement(Cluster) - mismatch labels",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcTPCluster, clusterV4), svcClusterIPFrontend(redSvcTPCluster, clusterV6)},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ClusterRP, redPeer65001v6ClusterRP},
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
							clusterV4PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4PrefixAggr)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6PrefixAggr: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6PrefixAggr)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ClusterRPAggr, redPeer65001v6ClusterRPAggr},
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
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ClusterRP, redPeer65001v6ClusterRP},
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
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ClusterRP, redPeer65001v6ClusterRP},
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
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ClusterRP, redPeer65001v6ClusterRP},
		},
		{
			name:      "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=local, ep on remote)",
			frontends: []*loadbalancer.Frontend{svcClusterIPFrontend(redSvcIntTPLocal, clusterV4), svcClusterIPFrontend(redSvcIntTPLocal, clusterV6)},
			backends:  redSvcBackendsRemote,
			advertisements: []*v2.CiliumBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name:       redPeer65001v4ClusterRPName + "-ipv4",
						Conditions: redPeer65001v4ClusterRP.Statement.Conditions,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddCommunities:      []string{"101:101", "202:202", "303:303", "no-export"},
							AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222", "3333:3333:3333"},
							SetLocalPreference:  &localPrefHigh,
						},
					},
				},
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name:       redPeer65001v6ClusterRPName + "-ipv6",
						Conditions: redPeer65001v6ClusterRP.Statement.Conditions,
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
				ServicePaths: ResourceAFPathsMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: PeerFamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
			ExpectedRoutePolicies: nil,
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
							clusterV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4ClusterRP, redPeer65001v6ClusterRP},
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
							clusterV4Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4ClusterRP,
				redPeer65001v6ClusterRP,
				redPeer65001v4ExtRP,
				redPeer65001v6ExtRP,
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
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							clusterV4Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.MustNewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4ClusterRP,
				redPeer65001v6ClusterRP,
				redPeer65001v4ExtRP,
				redPeer65001v6ExtRP,
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
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP, redPeer65001v6LBRP},
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
					redSvc2Key: AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4LBRP,
				redPeer65001v6LBRP,
				redPeer65001Svc2v4LBRP,
				redPeer65001Svc2v6LBRP,
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{redPeer65001Svc2v4LBRP, redPeer65001Svc2v6LBRP},
		},
		{
			name: "Delete service 2 (LoadBalancer, port 443)",
			deleteFrontends: []*loadbalancer.Frontend{
				svcFrontend(redSvc2TPCluster, ingressV4, 443, loadbalancer.SVCTypeLoadBalancer),
				svcFrontend(redSvc2TPCluster, ingressV6, 443, loadbalancer.SVCTypeLoadBalancer),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: ResourceAFPathsMap{},
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
			ExpectedRoutePolicies: nil,
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name:       redPeer65001v4LBRPName + "-ipv4",
						Conditions: redPeer65001v4LBRP.Statement.Conditions,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddCommunities:      []string{"101:101", "202:202", "no-export"},
							AddLargeCommunities: []string{"1111:1111:1111", "2222:2222:2222"},
							SetLocalPreference:  &localPrefHigh,
						},
					},
				},
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name:       redPeer65001v6LBRPName + "-ipv6",
						Conditions: redPeer65001v6LBRP.Statement.Conditions,
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name: redPeer65001v4LBRPName + "-ipv4",
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
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name: redPeer65001v6LBRPName + "-ipv6",
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
							ingressV4Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
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
			ExpectedRoutePolicies: []*bgpTables.DesiredRoutePolicy{
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name: redPeer65001v4LBRPName + "-ipv4",
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
				{
					Instance:   "fake-instance",
					Peer:       "red-peer-65001",
					PolicyType: types.RoutePolicyTypeExport,
					Priority:   ServiceReconcilerPriority,
					Owner:      ServiceReconcilerName,
					Resource:   redSvcKey,
					Statement: &types.RoutePolicyStatement{
						Name: redPeer65001v6LBRPName + "-ipv6",
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
	require.NoError(t, f.routePolicyReconciler.Init(testBGPInstance))
	t.Cleanup(func() {
		f.routePolicyReconciler.Cleanup(testBGPInstance)
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
						fe.Backends = concatBackend(fe.Backends, *be, nextBackendRevision)
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
			requireDesiredRoutePolicies(t, f.db, f.svcReconciler.desiredRoutePolicyTable,
				testBGPInstance.Name, f.svcReconciler.Name(), tt.ExpectedRoutePolicies)

			err := f.routePolicyReconciler.Reconcile(context.Background(), ReconcileParams{
				BGPInstance:   testBGPInstance,
				DesiredConfig: desiredConfig,
				CiliumNode:    testCiliumNodeConfig,
			})
			req.NoError(err)

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, f.svcReconciler.getMetadata(testBGPInstance))

			// validate that advertised paths match expected metadata
			advertisedPrefixesAndPathAttrMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)

			// validate that advertised policies match expected attributes
			advertisedPoliciesAttributesMatch(req, testBGPInstance, tt.ExpectedRoutePolicies)
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
				bgpTables.NewDesiredRoutePoliciesTable,

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
				f.routePolicyReconciler = NewRoutePolicyReconciler(RoutePolicyReconcilerIn{
					Logger:                  p.Logger,
					DB:                      f.svcReconciler.db,
					DesiredRoutePolicyTable: f.svcReconciler.desiredRoutePolicyTable,
				}).Reconciler.(*RoutePolicyReconciler)
			}),
		),
	)
	return f
}

func newTestBackend(svcName loadbalancer.ServiceName, addr loadbalancer.L3n4Addr, node string, state loadbalancer.BackendState) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		ServiceName: svcName,
		Address:     addr,
		NodeName:    node,
		PortNames:   nil,
		Weight:      0,
		State:       state,
		Source:      source.Kubernetes,
	}
}

func concatBackend(bes loadbalancer.BackendsSeq2, be loadbalancer.Backend, rev statedb.Revision) loadbalancer.BackendsSeq2 {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		if !yield(&be, rev) {
			return
		}
		bes(yield)
	}
}

func serviceMetadataEqual(req *require.Assertions, expectedMetadata ServiceReconcilerMetadata, runningMetadata ServiceReconcilerMetadata) {
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
	expectedRoutePolicies []*bgpTables.DesiredRoutePolicy,
) {
	response, err := bgpInstance.Router.GetRoutePolicies(context.Background())
	req.NoError(err)

	desiredStatementsByObject := make(map[routePolicyObjectKey][]*bgpTables.DesiredRoutePolicy)
	for _, statement := range expectedRoutePolicies {
		policyKey := getRoutePolicyObjectKey(statement)
		desiredStatementsByObject[policyKey] = append(desiredStatementsByObject[policyKey], statement)
	}

	expectedGroupedPolicies := make(RoutePolicyMap, len(desiredStatementsByObject))
	for policyKey, statements := range desiredStatementsByObject {
		policy, err := desiredRoutePolicyFromStatements(policyKey, statements)
		req.NoError(err)
		if policy != nil {
			expectedGroupedPolicies[policy.Name] = policy
		}
	}

	req.Len(response.Policies, len(expectedGroupedPolicies))
	for _, policy := range response.Policies {
		expectedPolicy, exists := expectedGroupedPolicies[policy.Name]
		req.Truef(exists, "unexpected route policy %q", policy.Name)
		req.Truef(policy.DeepEqual(expectedPolicy), "route policy %q mismatch, expected: %v, got: %v", policy.Name, expectedPolicy, policy)
	}
}

type failingFakeRouter struct {
	*fake.FakeRouter
	failPolicyName string
	failPrefix     string
}

func (r *failingFakeRouter) AddRoutePolicy(ctx context.Context, p types.RoutePolicyRequest) error {
	if p.Policy != nil && p.Policy.Name == r.failPolicyName {
		return errors.New("injected add route policy failure")
	}
	return r.FakeRouter.AddRoutePolicy(ctx, p)
}

func (r *failingFakeRouter) AdvertisePath(ctx context.Context, p types.PathRequest) (types.PathResponse, error) {
	if p.Path != nil && p.Path.NLRI.String() == r.failPrefix {
		return types.PathResponse{}, errors.New("injected advertise path failure")
	}
	return r.FakeRouter.AdvertisePath(ctx, p)
}

func TestServiceReconcilerMetadataPartialFailure(t *testing.T) {
	// runFailedReconcile runs a reconciliation attempt that should fail thanks to passed failingFakeRouter.
	// One aggregated service advertisement is being reconciled here.
	runFailedReconcile := func(t *testing.T, router *failingFakeRouter, initialMetadata ServiceReconcilerMetadata) ServiceReconcilerMetadata {
		t.Helper()
		req := require.New(t)

		f := newServiceTestFixture(t, bgpConfig())
		log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
		err := f.hive.Start(log, context.Background())
		req.NoError(err)
		t.Cleanup(func() {
			f.hive.Stop(log, context.Background())
		})

		testBGPInstance := instance.NewFakeBGPInstance()
		testBGPInstance.Router = router
		f.svcReconciler.Init(testBGPInstance)
		t.Cleanup(func() {
			f.svcReconciler.Cleanup(testBGPInstance)
		})

		// Upsert peer config and aggregation advertisement
		f.PeerConfigStore.Upsert(redPeerConfig)
		f.AdvertStore.Upsert(redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector, aggregation)))
		f.svcReconciler.setMetadata(testBGPInstance, initialMetadata)

		// Upser service frontend + backend
		frontend := svcLBFrontend(redSvcTPCluster, ingressV4)
		frontend.Backends = concatBackend(frontend.Backends, *newTestBackend(redSvcName, backendAddr("10.1.0.1", 80), "node1", loadbalancer.BackendStateActive), 1)
		tx := f.db.WriteTxn(f.frontends)
		_, _, err = f.frontends.Insert(tx, frontend)
		req.NoError(err)
		tx.Commit()

		// Run reconcile
		err = f.svcReconciler.Reconcile(t.Context(), ReconcileParams{
			BGPInstance:   testBGPInstance,
			DesiredConfig: testBGPInstanceConfig,
			CiliumNode:    testCiliumNodeConfig,
		})
		req.Error(err)

		return f.svcReconciler.getMetadata(testBGPInstance)
	}

	// This covers failed path replacement:
	// The old path is withdrawn, the replacement advertise fails during reconcile,
	// so metadata must not keep the withdrawn old path after reconcile.
	t.Run("advertise path failure", func(t *testing.T) {
		req := require.New(t)

		router := &failingFakeRouter{
			FakeRouter: fake.NewFakeRouter(),
			failPrefix: ingressV4PrefixAggr, // aggregation prefix will fail during reconcile
		}
		oldPath := types.MustNewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)) // non-aggregated prefix

		oldPolicy, err := desiredRoutePolicyFromStatements(
			getRoutePolicyObjectKey(redPeer65001v4LBRP),
			[]*bgpTables.DesiredRoutePolicy{redPeer65001v4LBRP},
		)
		req.NoError(err)
		req.NoError(router.FakeRouter.AddRoutePolicy(t.Context(), types.RoutePolicyRequest{
			Policy: oldPolicy,
		}))
		_, err = router.FakeRouter.AdvertisePath(t.Context(), types.PathRequest{
			Path: oldPath,
		})
		req.NoError(err)

		initialMetadata := ServiceReconcilerMetadata{
			ServicePaths: ResourceAFPathsMap{
				redSvcKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						ingressV4Prefix: oldPath,
					},
				},
			},
			ServiceAdvertisements: make(PeerAdvertisements),
		}
		newMetadata := runFailedReconcile(t, router, initialMetadata)

		// service prefix should be withdrawn from metadata as well as router now
		paths := newMetadata.ServicePaths[redSvcKey][types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast}]
		req.NotContains(paths, ingressV4Prefix)
		req.NotContains(paths, ingressV4PrefixAggr)

		routes, err := router.GetRoutes(t.Context(), &types.GetRoutesRequest{TableType: types.TableTypeLocRIB})
		req.NoError(err)
		req.Empty(routes.Routes)

		// ServiceAdvertisements should not update after failure, FrontendChangesInitialized should be false
		req.Empty(newMetadata.ServiceAdvertisements)
		req.False(newMetadata.FrontendChangesInitialized)
	})
}
