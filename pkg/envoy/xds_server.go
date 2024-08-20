// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_mysql_proxy "github.com/cilium/proxy/go/contrib/envoy/extensions/filters/network/mysql_proxy/v3"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	envoy_upstream_codec "github.com/cilium/proxy/go/envoy/extensions/filters/http/upstream_codec/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_mongo_proxy "github.com/cilium/proxy/go/envoy/extensions/filters/network/mongo_proxy/v3"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	_ "github.com/cilium/cilium/pkg/envoy/resource"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// allowAllPortNetworkPolicy is a PortNetworkPolicy that allows all traffic
	// to any L4 port.
	allowAllTCPPortNetworkPolicy = &cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		Protocol: envoy_config_core.SocketAddress_TCP,
	}
	allowAllPortNetworkPolicy = []*cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		allowAllTCPPortNetworkPolicy,
		// Allow all UDP/SCTP traffic to any port.
		// UDP/SCTP rules not sent to Envoy for now.
	}
)

const (
	CiliumXDSClusterName = "xds-grpc-cilium"

	adminClusterName      = "/envoy-admin"
	egressClusterName     = "egress-cluster"
	egressTLSClusterName  = "egress-cluster-tls"
	ingressClusterName    = "ingress-cluster"
	ingressTLSClusterName = "ingress-cluster-tls"
	metricsListenerName   = "envoy-prometheus-metrics-listener"
	adminListenerName     = "envoy-admin-listener"
)

type Listener struct {
	// must hold the xdsServer.mutex when accessing 'count'
	count uint

	// mutex is needed when accessing the fields below.
	// xdsServer.mutex is not needed, but if taken it must be taken before 'mutex'
	mutex   lock.RWMutex
	acked   bool
	nacked  bool
	waiters []*completion.Completion
}

// XDSServer provides a high-lever interface to manage resources published using the xDS gRPC API.
type XDSServer interface {
	// AddListener adds a listener to a running Envoy proxy.
	AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup)
	// AddAdminListener adds an Admin API listener to Envoy.
	AddAdminListener(port uint16, wg *completion.WaitGroup)
	// AddMetricsListener adds a prometheus metrics listener to Envoy.
	AddMetricsListener(port uint16, wg *completion.WaitGroup)
	// RemoveListener removes an existing Envoy Listener.
	RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc

	// UpsertEnvoyResources inserts or updates Envoy resources in 'resources' to the xDS cache,
	// from where they will be delivered to Envoy via xDS streaming gRPC.
	UpsertEnvoyResources(ctx context.Context, resources Resources) error
	// UpdateEnvoyResources removes any resources in 'old' that are not
	// present in 'new' and then adds or updates all resources in 'new'.
	// Envoy does not support changing the listening port of an existing
	// listener, so if the port changes we have to delete the old listener
	// and then add the new one with the new port number.
	UpdateEnvoyResources(ctx context.Context, old, new Resources) error
	// DeleteEnvoyResources deletes all Envoy resources in 'resources'.
	DeleteEnvoyResources(ctx context.Context, resources Resources) error

	// GetNetworkPolicies returns the current version of the network policies with the given names.
	// If resourceNames is empty, all resources are returned.
	//
	// Only used for testing
	GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error)
	// UpdateNetworkPolicy adds or updates a network policy in the set published to L7 proxies.
	// When the proxy acknowledges the network policy update, it will result in
	// a subsequent call to the endpoint's OnProxyPolicyUpdate() function.
	UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error)
	// RemoveNetworkPolicy removes network policies relevant to the specified
	// endpoint from the set published to L7 proxies, and stops listening for
	// acks for policies on this endpoint.
	RemoveNetworkPolicy(ep endpoint.EndpointInfoSource)
	// RemoveAllNetworkPolicies removes all network policies from the set published
	// to L7 proxies.
	RemoveAllNetworkPolicies()
}

type xdsServer struct {
	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// accessLogPath is the path to the L7 access logs
	accessLogPath string

	config xdsServerConfig

	// mutex protects accesses to the configuration resources below.
	mutex lock.RWMutex

	// listenerMutator publishes listener updates to Envoy proxies.
	// Manages it's own locking
	listenerMutator xds.AckingResourceMutator

	// routeMutator publishes route updates to Envoy proxies.
	// Manages it's own locking
	routeMutator xds.AckingResourceMutator

	// clusterMutator publishes cluster updates to Envoy proxies.
	// Manages it's own locking
	clusterMutator xds.AckingResourceMutator

	// endpointMutator publishes endpoint updates to Envoy proxies.
	// Manages it's own locking
	endpointMutator xds.AckingResourceMutator

	// secretMutator publishes secret updates to Envoy proxies.
	// Manages it's own locking
	secretMutator xds.AckingResourceMutator

	// listeners is the set of names of listeners that have been added by
	// calling AddListener.
	// mutex must be held when accessing this.
	// Value holds the number of redirects using the listener named by the key.
	listeners map[string]*Listener

	// proxyListeners is the count of redirection proxy listeners in 'listeners'.
	// When this is zero, cilium should not wait for NACKs/ACKs from envoy.
	// This value is different from len(listeners) due to non-proxy listeners
	// (e.g., prometheus listener)
	proxyListeners int

	// networkPolicyCache publishes network policy configuration updates to
	// Envoy proxies.
	networkPolicyCache *xds.Cache

	// NetworkPolicyMutator wraps networkPolicyCache to publish policy
	// updates to Envoy proxies.
	// Exported for testing only!
	NetworkPolicyMutator xds.AckingResourceMutator

	// stopFunc contains the function which stops the xDS gRPC server.
	stopFunc context.CancelFunc

	// IPCache is used for tracking IP->Identity mappings and propagating
	// them to the proxy via NPHDS in the cases described
	ipCache IPCacheEventSource

	restorerPromise promise.Promise[endpointstate.Restorer]

	localEndpointStore *LocalEndpointStore
}

func toAny(pb proto.Message) *anypb.Any {
	a, err := anypb.New(pb)
	if err != nil {
		panic(err.Error())
	}
	return a
}

type xdsServerConfig struct {
	envoySocketDir                string
	proxyGID                      int
	httpRequestTimeout            int
	httpIdleTimeout               int
	httpMaxGRPCTimeout            int
	httpRetryCount                int
	httpRetryTimeout              int
	httpNormalizePath             bool
	useFullTLSContext             bool
	proxyXffNumTrustedHopsIngress uint32
	proxyXffNumTrustedHopsEgress  uint32
}

// newXDSServer creates a new xDS GRPC server.
func newXDSServer(restorerPromise promise.Promise[endpointstate.Restorer], ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig) (*xdsServer, error) {
	return &xdsServer{
		restorerPromise:    restorerPromise,
		listeners:          make(map[string]*Listener),
		ipCache:            ipCache,
		localEndpointStore: localEndpointStore,

		socketPath:    getXDSSocketPath(config.envoySocketDir),
		accessLogPath: getAccessLogSocketPath(config.envoySocketDir),
		config:        config,
	}, nil
}

// start configures and starts the xDS GRPC server.
func (s *xdsServer) start() error {
	socketListener, err := s.newSocketListener()
	if err != nil {
		return fmt.Errorf("failed to create socket listener: %w", err)
	}

	resourceConfig := s.initializeXdsConfigs()

	s.stopFunc = s.startXDSGRPCServer(socketListener, resourceConfig)

	return nil
}

func (s *xdsServer) initializeXdsConfigs() map[string]*xds.ResourceTypeConfiguration {
	ldsCache := xds.NewCache()
	ldsMutator := xds.NewAckingResourceMutatorWrapper(ldsCache)
	ldsConfig := &xds.ResourceTypeConfiguration{
		Source:      ldsCache,
		AckObserver: ldsMutator,
	}

	rdsCache := xds.NewCache()
	rdsMutator := xds.NewAckingResourceMutatorWrapper(rdsCache)
	rdsConfig := &xds.ResourceTypeConfiguration{
		Source:      rdsCache,
		AckObserver: rdsMutator,
	}

	cdsCache := xds.NewCache()
	cdsMutator := xds.NewAckingResourceMutatorWrapper(cdsCache)
	cdsConfig := &xds.ResourceTypeConfiguration{
		Source:      cdsCache,
		AckObserver: cdsMutator,
	}

	edsCache := xds.NewCache()
	edsMutator := xds.NewAckingResourceMutatorWrapper(edsCache)
	edsConfig := &xds.ResourceTypeConfiguration{
		Source:      edsCache,
		AckObserver: edsMutator,
	}

	sdsCache := xds.NewCache()
	sdsMutator := xds.NewAckingResourceMutatorWrapper(sdsCache)
	sdsConfig := &xds.ResourceTypeConfiguration{
		Source:      sdsCache,
		AckObserver: sdsMutator,
	}

	npdsCache := xds.NewCache()
	npdsMutator := xds.NewAckingResourceMutatorWrapper(npdsCache)
	npdsConfig := &xds.ResourceTypeConfiguration{
		Source:      npdsCache,
		AckObserver: npdsMutator,
	}

	nphdsCache := newNPHDSCache(s.ipCache)
	nphdsConfig := &xds.ResourceTypeConfiguration{
		Source:      nphdsCache,
		AckObserver: &nphdsCache,
	}

	s.listenerMutator = ldsMutator
	s.routeMutator = rdsMutator
	s.clusterMutator = cdsMutator
	s.endpointMutator = edsMutator
	s.secretMutator = sdsMutator
	s.networkPolicyCache = npdsCache
	s.NetworkPolicyMutator = npdsMutator

	resourceConfig := map[string]*xds.ResourceTypeConfiguration{
		ListenerTypeURL:           ldsConfig,
		RouteTypeURL:              rdsConfig,
		ClusterTypeURL:            cdsConfig,
		EndpointTypeURL:           edsConfig,
		SecretTypeURL:             sdsConfig,
		NetworkPolicyTypeURL:      npdsConfig,
		NetworkPolicyHostsTypeURL: nphdsConfig,
	}
	return resourceConfig
}

func (s *xdsServer) newSocketListener() (*net.UnixListener, error) {
	// Remove/Unlink the old unix domain socket, if any.
	_ = os.Remove(s.socketPath)

	socketListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("failed to open xDS listen socket at %s: %w", s.socketPath, err)
	}

	// Make the socket accessible by owner and group only.
	if err = os.Chmod(s.socketPath, 0660); err != nil {
		return nil, fmt.Errorf("failed to change mode of xDS listen socket at %s: %w", s.socketPath, err)
	}
	// Change the group to ProxyGID allowing access from any process from that group.
	if err = os.Chown(s.socketPath, -1, s.config.proxyGID); err != nil {
		log.WithError(err).Warningf("Envoy: Failed to change the group of xDS listen socket at %s", s.socketPath)
	}
	return socketListener, nil
}

func (s *xdsServer) stop() {
	if s.stopFunc != nil {
		s.stopFunc()
	}
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath)
	}
}

func GetCiliumHttpFilter() *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "cilium.l7policy",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: toAny(&cilium.L7Policy{
				AccessLogPath:  getAccessLogSocketPath(GetSocketDir(option.Config.RunDir)),
				Denied_403Body: option.Config.HTTP403Message,
			}),
		},
	}
}

func GetUpstreamCodecFilter() *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "envoy.filters.http.upstream_codec",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: toAny(&envoy_upstream_codec.UpstreamCodec{}),
		},
	}
}

func (s *xdsServer) getHttpFilterChainProto(clusterName string, tls bool, isIngress bool) *envoy_config_listener.FilterChain {

	requestTimeout := int64(s.config.httpRequestTimeout) // seconds
	idleTimeout := int64(s.config.httpIdleTimeout)       // seconds
	maxGRPCTimeout := int64(s.config.httpMaxGRPCTimeout) // seconds
	numRetries := uint32(s.config.httpRetryCount)
	retryTimeout := int64(s.config.httpRetryTimeout) // seconds
	xffNumTrustedHops := s.config.proxyXffNumTrustedHopsEgress
	if isIngress {
		xffNumTrustedHops = s.config.proxyXffNumTrustedHopsIngress
	}

	hcmConfig := &envoy_config_http.HttpConnectionManager{
		StatPrefix:        "proxy",
		UseRemoteAddress:  &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:     true,
		XffNumTrustedHops: xffNumTrustedHops,
		HttpFilters: []*envoy_config_http.HttpFilter{
			GetCiliumHttpFilter(),
			{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
				},
			},
		},
		StreamIdleTimeout: &durationpb.Duration{}, // 0 == disabled
		RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route.RouteConfiguration{
				VirtualHosts: []*envoy_config_route.VirtualHost{{
					Name:    "default_route",
					Domains: []string{"*"},
					Routes: []*envoy_config_route.Route{{
						Match: &envoy_config_route.RouteMatch{
							PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/"},
							Grpc:          &envoy_config_route.RouteMatch_GrpcRouteMatchOptions{},
						},
						Action: &envoy_config_route.Route_Route{
							Route: &envoy_config_route.RouteAction{
								ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{
									Cluster: clusterName,
								},
								Timeout: &durationpb.Duration{Seconds: requestTimeout},
								MaxStreamDuration: &envoy_config_route.RouteAction_MaxStreamDuration{
									GrpcTimeoutHeaderMax: &durationpb.Duration{Seconds: maxGRPCTimeout},
								},
								RetryPolicy: &envoy_config_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrapperspb.UInt32Value{Value: numRetries},
									PerTryTimeout: &durationpb.Duration{Seconds: retryTimeout},
								},
							},
						},
					}, {
						Match: &envoy_config_route.RouteMatch{
							PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/"},
						},
						Action: &envoy_config_route.Route_Route{
							Route: &envoy_config_route.RouteAction{
								ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{
									Cluster: clusterName,
								},
								Timeout: &durationpb.Duration{Seconds: requestTimeout},
								// IdleTimeout: &durationpb.Duration{Seconds: idleTimeout},
								RetryPolicy: &envoy_config_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrapperspb.UInt32Value{Value: numRetries},
									PerTryTimeout: &durationpb.Duration{Seconds: retryTimeout},
								},
							},
						},
					}},
				}},
			},
		},
	}

	if s.config.httpNormalizePath {
		hcmConfig.NormalizePath = &wrapperspb.BoolValue{Value: true}
		hcmConfig.MergeSlashes = true
		hcmConfig.PathWithEscapedSlashesAction = envoy_config_http.HttpConnectionManager_UNESCAPE_AND_REDIRECT
	}

	// Idle timeout can only be specified if non-zero
	if idleTimeout > 0 {
		hcmConfig.GetRouteConfig().VirtualHosts[0].Routes[1].GetRoute().IdleTimeout = &durationpb.Duration{Seconds: idleTimeout}
	}

	chain := &envoy_config_listener.FilterChain{
		Filters: []*envoy_config_listener.Filter{{
			Name: "cilium.network",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: toAny(&cilium.NetworkFilter{}),
			},
		}, {
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: toAny(hcmConfig),
			},
		}},
	}

	if tls {
		chain.FilterChainMatch = &envoy_config_listener.FilterChainMatch{
			TransportProtocol: "tls",
		}
		chain.TransportSocket = &envoy_config_core.TransportSocket{
			Name: "cilium.tls_wrapper",
			ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
				TypedConfig: toAny(&cilium.DownstreamTlsWrapperContext{}),
			},
		}
	}

	return chain
}

// getTcpFilterChainProto creates a TCP filter chain with the Cilium network filter.
// By default, the returned chain can be used with the Cilium Go extensions L7 parsers
// in 'proxylib' directory in the Cilium repo.
// When optional 'filterName' is given, it is configured as the first filter in the chain
// and 'proxylib' is not configured. In this case the returned filter chain is only used
// if the applicable network policy specifies 'filterName' as the L7 parser.
func (s *xdsServer) getTcpFilterChainProto(clusterName string, filterName string, config *anypb.Any, tls bool) *envoy_config_listener.FilterChain {
	var filters []*envoy_config_listener.Filter

	// 1. Add the filter 'filterName' to the beginning of the TCP chain with optional 'config', if needed.
	if filterName != "" {
		filter := &envoy_config_listener.Filter{Name: filterName}
		if config != nil {
			filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: config,
			}
		}
		filters = append(filters, filter)
	}

	// 2. Add Cilium Network filter.
	var ciliumConfig *cilium.NetworkFilter
	if filterName == "" {
		// Use proxylib by default
		ciliumConfig = &cilium.NetworkFilter{
			Proxylib: "libcilium.so",
			ProxylibParams: map[string]string{
				"access-log-path": s.accessLogPath,
				"xds-path":        s.socketPath,
			},
		}
	} else {
		// Envoy metadata logging requires accesslog path
		ciliumConfig = &cilium.NetworkFilter{
			AccessLogPath: s.accessLogPath,
		}
	}
	filters = append(filters, &envoy_config_listener.Filter{
		Name: "cilium.network",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: toAny(ciliumConfig),
		},
	})

	// 3. Add the TCP proxy filter.
	filters = append(filters, &envoy_config_listener.Filter{
		Name: "envoy.filters.network.tcp_proxy",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: toAny(&envoy_config_tcp.TcpProxy{
				StatPrefix: "tcp_proxy",
				ClusterSpecifier: &envoy_config_tcp.TcpProxy_Cluster{
					Cluster: clusterName,
				},
			}),
		},
	})

	chain := &envoy_config_listener.FilterChain{
		Filters: filters,
	}

	if tls {
		chain.FilterChainMatch = &envoy_config_listener.FilterChainMatch{
			TransportProtocol: "tls",
		}
		chain.TransportSocket = &envoy_config_core.TransportSocket{
			Name: "cilium.tls_wrapper",
			ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
				TypedConfig: toAny(&cilium.DownstreamTlsWrapperContext{}),
			},
		}
	} else {
		chain.FilterChainMatch = &envoy_config_listener.FilterChainMatch{
			// must have transport match for non-TLS,
			// otherwise TLS inspector will be automatically inserted
			TransportProtocol: "raw_buffer",
		}
	}

	if filterName != "" {
		// Add filter chain match for 'filterName' so that connections for which policy says to use this L7
		// are handled by this filter chain.
		chain.FilterChainMatch.ApplicationProtocols = []string{filterName}
	}

	return chain
}

func getPublicListenerAddress(port uint16, ipv4, ipv6 bool) *envoy_config_core.Address {
	listenerAddr := "0.0.0.0"
	if ipv6 {
		listenerAddr = "::"
	}
	return &envoy_config_core.Address{
		Address: &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       listenerAddr,
				Ipv4Compat:    ipv4 && ipv6,
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		},
	}
}

func GetLocalListenerAddresses(port uint16, ipv4, ipv6 bool) (*envoy_config_core.Address, []*envoy_config_listener.AdditionalAddress) {
	addresses := []*envoy_config_core.Address_SocketAddress{}

	if ipv4 {
		addresses = append(addresses, &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       "127.0.0.1",
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		})
	}

	if ipv6 {
		addresses = append(addresses, &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       "::1",
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		})
	}

	var additionalAddress []*envoy_config_listener.AdditionalAddress

	if len(addresses) > 1 {
		additionalAddress = append(additionalAddress, &envoy_config_listener.AdditionalAddress{
			Address: &envoy_config_core.Address{
				Address: addresses[1],
			},
		})
	}

	return &envoy_config_core.Address{
		Address: addresses[0],
	}, additionalAddress
}

func (s *xdsServer) AddAdminListener(port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	log.WithField(logfields.Port, port).Debug("Envoy: AddAdminListener")

	s.addListener(adminListenerName, func() *envoy_config_listener.Listener {
		hcmConfig := &envoy_config_http.HttpConnectionManager{
			StatPrefix:       adminListenerName,
			UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
			SkipXffAppend:    true,
			HttpFilters: []*envoy_config_http.HttpFilter{{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
				},
			}},
			StreamIdleTimeout: &durationpb.Duration{}, // 0 == disabled
			RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{
				RouteConfig: &envoy_config_route.RouteConfiguration{
					VirtualHosts: []*envoy_config_route.VirtualHost{{
						Name:    "admin_listener_route",
						Domains: []string{"*"},
						Routes: []*envoy_config_route.Route{{
							Match: &envoy_config_route.RouteMatch{
								PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/"},
							},
							Action: &envoy_config_route.Route_Route{
								Route: &envoy_config_route.RouteAction{
									ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{
										Cluster: adminClusterName,
									},
								},
							},
						}},
					}},
				},
			},
		}

		addr, additionalAddr := GetLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
		listenerConf := &envoy_config_listener.Listener{
			Name:                adminListenerName,
			Address:             addr,
			AdditionalAddresses: additionalAddr,
			FilterChains: []*envoy_config_listener.FilterChain{{
				Filters: []*envoy_config_listener.Filter{{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: toAny(hcmConfig),
					},
				}},
			}},
		}

		return listenerConf
	}, wg, func(err error) {
		if err != nil {
			log.WithField(logfields.Port, port).WithError(err).Debug("Envoy: Adding admin listener failed")
			// Remove the added listener in case of a failure
			s.removeListener(adminListenerName, nil, false)
		} else {
			log.WithField(logfields.Port, port).Info("Envoy: Listening for Admin API")
		}
	}, false)
}

func (s *xdsServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	log.WithField(logfields.Port, port).Debug("Envoy: AddMetricsListener")

	s.addListener(metricsListenerName, func() *envoy_config_listener.Listener {
		hcmConfig := &envoy_config_http.HttpConnectionManager{
			StatPrefix:       metricsListenerName,
			UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
			SkipXffAppend:    true,
			HttpFilters: []*envoy_config_http.HttpFilter{{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
				},
			}},
			StreamIdleTimeout: &durationpb.Duration{}, // 0 == disabled
			RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{
				RouteConfig: &envoy_config_route.RouteConfiguration{
					VirtualHosts: []*envoy_config_route.VirtualHost{{
						Name:    "prometheus_metrics_route",
						Domains: []string{"*"},
						Routes: []*envoy_config_route.Route{{
							Match: &envoy_config_route.RouteMatch{
								PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/metrics"},
							},
							Action: &envoy_config_route.Route_Route{
								Route: &envoy_config_route.RouteAction{
									ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{
										Cluster: adminClusterName,
									},
									PrefixRewrite: "/stats/prometheus",
								},
							},
						}},
					}},
				},
			},
		}

		listenerConf := &envoy_config_listener.Listener{
			Name:    metricsListenerName,
			Address: getPublicListenerAddress(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled()),
			FilterChains: []*envoy_config_listener.FilterChain{{
				Filters: []*envoy_config_listener.Filter{{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: toAny(hcmConfig),
					},
				}},
			}},
		}

		return listenerConf
	}, wg, func(err error) {
		if err != nil {
			log.WithField(logfields.Port, port).WithError(err).Debug("Envoy: Adding metrics listener failed")
			// Remove the added listener in case of a failure
			s.removeListener(metricsListenerName, nil, false)
		} else {
			log.WithField(logfields.Port, port).Info("Envoy: Listening for prometheus metrics")
		}
	}, false)
}

// addListener either reuses an existing listener with 'name', or creates a new one.
// 'listenerConf()' is only called if a new listener is being created.
func (s *xdsServer) addListener(name string, listenerConf func() *envoy_config_listener.Listener, wg *completion.WaitGroup, cb func(err error), isProxyListener bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	listener := s.listeners[name]
	if listener == nil {
		listener = &Listener{}
		s.listeners[name] = listener
		if isProxyListener {
			s.proxyListeners++
		}
	}
	listener.count++
	listener.mutex.Lock() // needed for other than 'count'
	if listener.count > 1 && !listener.nacked {
		log.Debugf("Envoy: Reusing listener: %s", name)
		call := true
		if !listener.acked {
			// Listener not acked yet, add a completion to the waiter's list
			log.Debugf("Envoy: Waiting for a non-acknowledged reused listener: %s", name)
			listener.waiters = append(listener.waiters, wg.AddCompletionWithCallback(cb))
			call = false
		}
		listener.mutex.Unlock()

		// call the callback with nil error if the listener was acked already
		if call && cb != nil {
			cb(nil)
		}
		return
	}
	// Try again after a NACK, potentially with a different port number, etc.
	if listener.nacked {
		listener.acked = false
		listener.nacked = false
	}
	listener.mutex.Unlock() // Listener locked again in callbacks below

	listenerConfig := listenerConf()
	if option.Config.EnableBPFTProxy {
		// Envoy since 1.20.0 uses SO_REUSEPORT on listeners by default.
		// BPF TPROXY is currently not compatible with SO_REUSEPORT, so disable it.
		// Note that this may degrade Envoy performance.
		listenerConfig.EnableReusePort = &wrapperspb.BoolValue{Value: false}
	}
	if err := listenerConfig.Validate(); err != nil {
		log.Errorf("Envoy: Could not validate Listener (%s): %s", err, listenerConfig.String())
		if cb != nil {
			cb(err)
		}
		return
	}

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConfig, []string{"127.0.0.1"}, wg,
		func(err error) {
			// listener might have already been removed, so we can't look again
			// but we still need to complete all the completions in case
			// someone is still waiting!
			listener.mutex.Lock()
			if err == nil {
				// Allow future users to not need to wait
				listener.acked = true
			} else {
				// Prevent further reuse of a failed listener
				listener.nacked = true
			}
			// Pass the completion result to all the additional waiters.
			for _, waiter := range listener.waiters {
				_ = waiter.Complete(err)
			}
			listener.waiters = nil
			listener.mutex.Unlock()

			if cb != nil {
				cb(err)
			}
		})
}

// upsertListener either updates an existing LDS listener with 'name', or creates a new one.
func (s *xdsServer) upsertListener(name string, listenerConf *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg, callback)
}

// deleteListener deletes an LDS Envoy Listener.
func (s *xdsServer) deleteListener(name string, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg, callback)
}

// upsertRoute either updates an existing RDS route with 'name', or creates a new one.
func (s *xdsServer) upsertRoute(name string, conf *envoy_config_route.RouteConfiguration, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.routeMutator.Upsert(RouteTypeURL, name, conf, []string{"127.0.0.1"}, wg, callback)
}

// deleteRoute deletes an RDS Route.
func (s *xdsServer) deleteRoute(name string, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.routeMutator.Delete(RouteTypeURL, name, []string{"127.0.0.1"}, wg, callback)
}

// upsertCluster either updates an existing CDS cluster with 'name', or creates a new one.
func (s *xdsServer) upsertCluster(name string, conf *envoy_config_cluster.Cluster, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.clusterMutator.Upsert(ClusterTypeURL, name, conf, []string{"127.0.0.1"}, wg, callback)
}

// deleteCluster deletes an CDS cluster.
func (s *xdsServer) deleteCluster(name string, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.clusterMutator.Delete(ClusterTypeURL, name, []string{"127.0.0.1"}, wg, callback)
}

// upsertEndpoint either updates an existing EDS endpoint with 'name', or creates a new one.
func (s *xdsServer) upsertEndpoint(name string, conf *envoy_config_endpoint.ClusterLoadAssignment, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.endpointMutator.Upsert(EndpointTypeURL, name, conf, []string{"127.0.0.1"}, wg, callback)
}

// deleteEndpoint deletes an EDS endpoint.
func (s *xdsServer) deleteEndpoint(name string, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.endpointMutator.Delete(EndpointTypeURL, name, []string{"127.0.0.1"}, wg, callback)
}

// upsertSecret either updates an existing SDS secret with 'name', or creates a new one.
func (s *xdsServer) upsertSecret(name string, conf *envoy_config_tls.Secret, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.secretMutator.Upsert(SecretTypeURL, name, conf, []string{"127.0.0.1"}, wg, callback)
}

// deleteSecret deletes an SDS secret.
func (s *xdsServer) deleteSecret(name string, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// 'callback' is not called if there is no change and this configuration has already been acked.
	return s.secretMutator.Delete(SecretTypeURL, name, []string{"127.0.0.1"}, wg, callback)
}

func getListenerFilter(isIngress bool, useOriginalSourceAddr bool, proxyPort uint16) *envoy_config_listener.ListenerFilter {
	conf := &cilium.BpfMetadata{
		IsIngress:                isIngress,
		UseOriginalSourceAddress: useOriginalSourceAddr,
		BpfRoot:                  bpf.BPFFSRoot(),
		IsL7Lb:                   false,
		ProxyId:                  uint32(proxyPort),
	}

	return &envoy_config_listener.ListenerFilter{
		Name: "cilium.bpf_metadata",
		ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
			TypedConfig: toAny(conf),
		},
	}
}

func (s *xdsServer) getListenerConf(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool) *envoy_config_listener.Listener {
	clusterName := egressClusterName
	tlsClusterName := egressTLSClusterName

	if isIngress {
		clusterName = ingressClusterName
		tlsClusterName = ingressTLSClusterName
	}

	addr, additionalAddr := GetLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
	listenerConf := &envoy_config_listener.Listener{
		Name:                name,
		Address:             addr,
		AdditionalAddresses: additionalAddr,
		// FilterChains: []*envoy_config_listener.FilterChain
		ListenerFilters: []*envoy_config_listener.ListenerFilter{
			// Always insert tls_inspector as the first filter
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
			getListenerFilter(isIngress, mayUseOriginalSourceAddr, port),
		},
	}

	// Add filter chains
	if kind == policy.ParserTypeHTTP {
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(clusterName, false, isIngress))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(tlsClusterName, true, isIngress))
	} else {
		// Default TCP chain, takes care of all parsers in proxylib
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName, "", nil, false))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(tlsClusterName, "", nil, true))

		// Experimental TCP chain for MySQL 5.x
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName,
			"envoy.filters.network.mysql_proxy", toAny(&envoy_mysql_proxy.MySQLProxy{
				StatPrefix: "mysql",
			}), false))

		// Experimental TCP chain for MongoDB
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName,
			"envoy.filters.network.mongo_proxy", toAny(&envoy_mongo_proxy.MongoProxy{
				StatPrefix:          "mongo",
				EmitDynamicMetadata: true,
			}), false))
	}
	return listenerConf
}

func (s *xdsServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) {
	log.Debugf("Envoy: %s AddListener %s (mayUseOriginalSourceAddr: %v)", kind, name, mayUseOriginalSourceAddr)

	s.addListener(name, func() *envoy_config_listener.Listener {
		return s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr)
	}, wg, nil, true)
}

func (s *xdsServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	return s.removeListener(name, wg, true)
}

// removeListener removes an existing Envoy Listener.
func (s *xdsServer) removeListener(name string, wg *completion.WaitGroup, isProxyListener bool) xds.AckingResourceMutatorRevertFunc {
	log.Debugf("Envoy: RemoveListener %s", name)

	var listenerRevertFunc xds.AckingResourceMutatorRevertFunc

	s.mutex.Lock()
	listener, ok := s.listeners[name]
	if ok && listener != nil {
		listener.count--
		if listener.count == 0 {
			if isProxyListener {
				s.proxyListeners--
			}
			delete(s.listeners, name)
			listenerRevertFunc = s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg, nil)
		}
	} else {
		// Bail out if this listener does not exist
		log.Fatalf("Envoy: Attempt to remove non-existent listener: %s", name)
	}
	s.mutex.Unlock()

	return func(completion *completion.Completion) {
		s.mutex.Lock()
		if listenerRevertFunc != nil {
			listenerRevertFunc(completion)
			if isProxyListener {
				s.proxyListeners++
			}
		}
		listener.count++
		s.listeners[name] = listener
		s.mutex.Unlock()
	}
}

func getL7Rules(l7Rules []api.PortRuleL7, l7Proto string) *cilium.L7NetworkPolicyRules {
	allowRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	denyRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	useEnvoyMetadataMatcher := false
	if strings.HasPrefix(l7Proto, "envoy.") {
		useEnvoyMetadataMatcher = true
	}
	for _, l7 := range l7Rules {
		if useEnvoyMetadataMatcher {
			envoyFilterName := l7Proto
			rule := &cilium.L7NetworkPolicyRule{MetadataRule: make([]*envoy_type_matcher.MetadataMatcher, 0, len(l7))}
			denyRule := false
			for k, v := range l7 {
				switch k {
				case "action":
					switch v {
					case "deny":
						denyRule = true
					}
				default:
					// map key to path segments and value to value matcher
					// For now only one path segment is allowed
					segments := strings.Split(k, "/")
					var path []*envoy_type_matcher.MetadataMatcher_PathSegment
					for _, key := range segments {
						path = append(path, &envoy_type_matcher.MetadataMatcher_PathSegment{
							Segment: &envoy_type_matcher.MetadataMatcher_PathSegment_Key{Key: key},
						})
					}
					var value *envoy_type_matcher.ValueMatcher
					if len(v) == 0 {
						value = &envoy_type_matcher.ValueMatcher{
							MatchPattern: &envoy_type_matcher.ValueMatcher_PresentMatch{
								PresentMatch: true,
							},
						}
					} else {
						value = &envoy_type_matcher.ValueMatcher{
							MatchPattern: &envoy_type_matcher.ValueMatcher_ListMatch{
								ListMatch: &envoy_type_matcher.ListMatcher{
									MatchPattern: &envoy_type_matcher.ListMatcher_OneOf{
										OneOf: &envoy_type_matcher.ValueMatcher{
											MatchPattern: &envoy_type_matcher.ValueMatcher_StringMatch{
												StringMatch: &envoy_type_matcher.StringMatcher{
													MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
														Exact: v,
													},
													IgnoreCase: false,
												},
											},
										},
									},
								},
							},
						}
					}
					rule.MetadataRule = append(rule.MetadataRule, &envoy_type_matcher.MetadataMatcher{
						Filter: envoyFilterName,
						Path:   path,
						Value:  value,
					})
				}
			}
			if denyRule {
				denyRules = append(denyRules, rule)
			} else {
				allowRules = append(allowRules, rule)
			}
		} else {
			// proxylib go extension key/value policy
			rule := &cilium.L7NetworkPolicyRule{Rule: make(map[string]string, len(l7))}
			for k, v := range l7 {
				rule.Rule[k] = v
			}
			allowRules = append(allowRules, rule)
		}
	}

	rules := &cilium.L7NetworkPolicyRules{}
	if len(allowRules) > 0 {
		rules.L7AllowRules = allowRules
	}
	if len(denyRules) > 0 {
		rules.L7DenyRules = denyRules
	}
	return rules
}

func getKafkaL7Rules(l7Rules []kafka.PortRule) *cilium.KafkaNetworkPolicyRules {
	allowRules := make([]*cilium.KafkaNetworkPolicyRule, 0, len(l7Rules))
	for _, kr := range l7Rules {
		rule := &cilium.KafkaNetworkPolicyRule{
			ApiVersion: kr.GetAPIVersion(),
			ApiKeys:    kr.GetAPIKeys(),
			ClientId:   kr.ClientID,
			Topic:      kr.Topic,
		}
		allowRules = append(allowRules, rule)
	}

	rules := &cilium.KafkaNetworkPolicyRules{}
	if len(allowRules) > 0 {
		rules.KafkaRules = allowRules
	}
	return rules
}

func getSecretString(secretManager certificatemanager.SecretManager, hdr *api.HeaderMatch, ns string) (string, error) {
	value := ""
	var err error
	if hdr.Secret != nil {
		if secretManager == nil {
			err = fmt.Errorf("HeaderMatches: Nil secretManager")
		} else {
			value, err = secretManager.GetSecretString(context.TODO(), hdr.Secret, ns)
		}
	}
	// Only use Value if secret was not obtained
	if value == "" && hdr.Value != "" {
		value = hdr.Value
		if err != nil {
			log.WithError(err).Debug("HeaderMatches: Using a default value due to k8s secret not being available")
			err = nil
		}
	}

	return value, err
}

func getHTTPRule(secretManager certificatemanager.SecretManager, h *api.PortRuleHTTP, ns string) (*cilium.HttpNetworkPolicyRule, bool) {
	// Count the number of header matches we need
	cnt := len(h.Headers) + len(h.HeaderMatches)
	if h.Path != "" {
		cnt++
	}
	if h.Method != "" {
		cnt++
	}
	if h.Host != "" {
		cnt++
	}

	headers := make([]*envoy_config_route.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":path",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher.StringMatcher{
					MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher.RegexMatcher{
							Regex: h.Path,
						},
					},
				},
			},
		})
	}
	if h.Method != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":method",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher.StringMatcher{
					MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher.RegexMatcher{
							Regex: h.Method,
						},
					},
				},
			},
		})
	}
	if h.Host != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":authority",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher.StringMatcher{
					MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher.RegexMatcher{
							Regex: h.Host,
						},
					},
				},
			},
		})
	}
	for _, hdr := range h.Headers {
		strs := strings.SplitN(hdr, " ", 2)
		if len(strs) == 2 {
			// Remove ':' in "X-Key: true"
			key := strings.TrimRight(strs[0], ":")
			// Header presence and matching (literal) value needed.
			headers = append(headers, &envoy_config_route.HeaderMatcher{
				Name: key,
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher.StringMatcher{
						MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
							Exact: strs[1],
						},
					},
				},
			})
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_config_route.HeaderMatcher{
				Name:                 strs[0],
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
			})
		}
	}

	headerMatches := make([]*cilium.HeaderMatch, 0, len(h.HeaderMatches))
	for _, hdr := range h.HeaderMatches {
		var mismatch_action cilium.HeaderMatch_MismatchAction
		switch hdr.Mismatch {
		case api.MismatchActionLog:
			mismatch_action = cilium.HeaderMatch_CONTINUE_ON_MISMATCH
		case api.MismatchActionAdd:
			mismatch_action = cilium.HeaderMatch_ADD_ON_MISMATCH
		case api.MismatchActionDelete:
			mismatch_action = cilium.HeaderMatch_DELETE_ON_MISMATCH
		case api.MismatchActionReplace:
			mismatch_action = cilium.HeaderMatch_REPLACE_ON_MISMATCH
		default:
			mismatch_action = cilium.HeaderMatch_FAIL_ON_MISMATCH
		}
		// Fetch the secret
		value, err := getSecretString(secretManager, hdr, ns)
		if err != nil {
			log.WithError(err).Warning("Failed fetching K8s Secret, header match will fail")
			// Envoy treats an empty exact match value as matching ANY value; adding
			// InvertMatch: true here will cause this rule to NEVER match.
			headers = append(headers, &envoy_config_route.HeaderMatcher{
				Name: hdr.Name,
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher.StringMatcher{
						MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
							Exact: "",
						},
					},
				},
				InvertMatch: true,
			})
		} else {
			// Header presence and matching (literal) value needed.
			if mismatch_action == cilium.HeaderMatch_FAIL_ON_MISMATCH {
				if value != "" {
					headers = append(headers, &envoy_config_route.HeaderMatcher{
						Name: hdr.Name,
						HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher.StringMatcher{
								MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
									Exact: value,
								},
							},
						},
					})
				} else {
					// Only header presence needed
					headers = append(headers, &envoy_config_route.HeaderMatcher{
						Name:                 hdr.Name,
						HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
					})
				}
			} else {
				log.Debugf("HeaderMatches: Adding %s", hdr.Name)
				headerMatches = append(headerMatches, &cilium.HeaderMatch{
					MismatchAction: mismatch_action,
					Name:           hdr.Name,
					Value:          value,
				})
			}
		}
	}
	if len(headers) == 0 {
		headers = nil
	} else {
		SortHeaderMatchers(headers)
	}
	if len(headerMatches) == 0 {
		headerMatches = nil
	} else {
		// Optimally we should sort the headerMatches to avoid
		// updating the policy if only the order of the rules
		// has changed. Right now, when 'headerMatches' is a
		// slice (rather than a map) the order only changes if
		// the order of the rules in the imported policies
		// changes, so there is minimal likelihood of
		// unnecessary policy updates.

		// SortHeaderMatches(headerMatches)
	}

	return &cilium.HttpNetworkPolicyRule{Headers: headers, HeaderMatches: headerMatches}, len(headerMatches) == 0
}

var CiliumXDSConfigSource = &envoy_config_core.ConfigSource{
	ResourceApiVersion: envoy_config_core.ApiVersion_V3,
	ConfigSourceSpecifier: &envoy_config_core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &envoy_config_core.ApiConfigSource{
			ApiType:                   envoy_config_core.ApiConfigSource_GRPC,
			TransportApiVersion:       envoy_config_core.ApiVersion_V3,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*envoy_config_core.GrpcService{
				{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
							ClusterName: CiliumXDSClusterName,
						},
					},
				},
			},
		},
	},
}

// toEnvoyFullTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) into a "cilium envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// Deprecated: This includes both the CA *and* the cert/key. You almost certainly don't want this. Use
// toEnvoyOriginatingTLSContext or toEnvoyTerminatingTLSContext instead.
// x-ref: https://github.com/cilium/cilium/issues/31761
func toEnvoyFullTLSContext(tls *policy.TLSContext) *cilium.TLSContext {
	return &cilium.TLSContext{
		TrustedCa:        tls.TrustedCA,
		CertificateChain: tls.CertificateChain,
		PrivateKey:       tls.PrivateKey,
	}
}

// toEnvoyOriginatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for originating TLS (i.e., verifying TLS connections from *outside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
func toEnvoyOriginatingTLSContext(tls *policy.TLSContext) *cilium.TLSContext {
	return &cilium.TLSContext{
		TrustedCa: tls.TrustedCA,
	}
}

// toEnvoyTerminatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for terminating TLS (i.e., providing a valid cert to clients *inside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
func toEnvoyTerminatingTLSContext(tls *policy.TLSContext) *cilium.TLSContext {
	return &cilium.TLSContext{
		CertificateChain: tls.CertificateChain,
		PrivateKey:       tls.PrivateKey,
	}
}

func GetEnvoyHTTPRules(secretManager certificatemanager.SecretManager, l7Rules *api.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool) {
	if len(l7Rules.HTTP) > 0 { // Just cautious. This should never be false.
		// Assume none of the rules have side-effects so that rule evaluation can
		// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
		// is set to 'false' below if any rules with side effects are encountered,
		// causing all the applicable rules to be evaluated instead.
		canShortCircuit := true
		httpRules := make([]*cilium.HttpNetworkPolicyRule, 0, len(l7Rules.HTTP))
		for _, l7 := range l7Rules.HTTP {
			var cs bool
			rule, cs := getHTTPRule(secretManager, &l7, ns)
			httpRules = append(httpRules, rule)
			if !cs {
				canShortCircuit = false
			}
		}
		SortHTTPNetworkPolicyRules(httpRules)
		return &cilium.HttpNetworkPolicyRules{
			HttpRules: httpRules,
		}, canShortCircuit
	}
	return nil, true
}

func getPortNetworkPolicyRule(sel policy.CachedSelector, wildcard bool, l7Parser policy.L7ParserType, l7Rules *policy.PerSelectorPolicy, useFullTLSContext bool) (*cilium.PortNetworkPolicyRule, bool) {
	r := &cilium.PortNetworkPolicyRule{}

	// Optimize the policy if the endpoint selector is a wildcard by
	// keeping remote policies list empty to match all remote policies.
	if !wildcard {
		selections := sel.GetSelections()

		// No remote policies would match this rule. Discard it.
		if len(selections) == 0 {
			return nil, true
		}

		r.RemotePolicies = selections.AsUint32Slice()
	}

	if l7Rules == nil {
		// L3/L4 only rule, everything in L7 is allowed && no TLS
		return r, true
	}

	if l7Rules.IsDeny {
		r.Deny = true
		return r, false
	}

	if useFullTLSContext {
		// Intentionally retain compatibility with older, buggy behaviour. In this mode the full contents of the
		// Kubernetes secret identified by TLS context is copied into the downstream/upstream TLS context. For the
		// downstream (i.e., in-cluster pod) this could include a CA bundle if a ca.crt key is present in the secret,
		// which may incorrectly lead Envoy to require client certificates.
		if l7Rules.TerminatingTLS != nil {
			r.DownstreamTlsContext = toEnvoyFullTLSContext(l7Rules.TerminatingTLS)
		}
		if l7Rules.OriginatingTLS != nil {
			r.UpstreamTlsContext = toEnvoyFullTLSContext(l7Rules.OriginatingTLS)
		}
	} else {
		if l7Rules.TerminatingTLS != nil {
			r.DownstreamTlsContext = toEnvoyTerminatingTLSContext(l7Rules.TerminatingTLS)
		}
		if l7Rules.OriginatingTLS != nil {
			r.UpstreamTlsContext = toEnvoyOriginatingTLSContext(l7Rules.OriginatingTLS)
		}
	}
	if len(l7Rules.ServerNames) > 0 {
		r.ServerNames = make([]string, 0, len(l7Rules.ServerNames))
		for sni := range l7Rules.ServerNames {
			r.ServerNames = append(r.ServerNames, sni)
		}
		sort.Strings(r.ServerNames)
	}

	// Assume none of the rules have side-effects so that rule evaluation can
	// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
	// is set to 'false' below if any rules with side effects are encountered,
	// causing all the applicable rules to be evaluated instead.
	canShortCircuit := true
	switch l7Parser {
	case policy.ParserTypeHTTP:
		// 'r.L7' is an interface which must not be set to a typed 'nil',
		// so check if we have any rules
		if len(l7Rules.HTTP) > 0 {
			// Use L7 rules computed earlier?
			var httpRules *cilium.HttpNetworkPolicyRules
			if l7Rules.EnvoyHTTPRules != nil {
				httpRules = l7Rules.EnvoyHTTPRules
				canShortCircuit = l7Rules.CanShortCircuit
			} else {
				httpRules, canShortCircuit = GetEnvoyHTTPRules(nil, &l7Rules.L7Rules, "")
			}
			r.L7 = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: httpRules,
			}
		}

	case policy.ParserTypeKafka:
		// Kafka is implemented as an Envoy Go Extension
		if len(l7Rules.Kafka) > 0 {
			// L7 rules are not sorted
			r.L7Proto = l7Parser.String()
			r.L7 = &cilium.PortNetworkPolicyRule_KafkaRules{
				KafkaRules: getKafkaL7Rules(l7Rules.Kafka),
			}
		}

	case policy.ParserTypeDNS:
		// TODO: Support DNS. For now, just ignore any DNS L7 rule.

	default:
		// Assume unknown parser types use a Key-Value Pair policy
		if len(l7Rules.L7) > 0 {
			// L7 rules are not sorted
			r.L7Proto = l7Parser.String()
			r.L7 = &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: getL7Rules(l7Rules.L7, r.L7Proto),
			}
		}
	}

	return r, canShortCircuit
}

// getWildcardNetworkPolicyRule returns the rule for port 0, which
// will be considered after port-specific rules.
func getWildcardNetworkPolicyRule(selectors policy.L7DataMap) *cilium.PortNetworkPolicyRule {
	// selections are pre-sorted, so sorting is only needed if merging selections from multiple selectors
	if len(selectors) == 1 {
		for sel := range selectors {
			if sel.IsWildcard() {
				return &cilium.PortNetworkPolicyRule{}
			}
			selections := sel.GetSelections()
			if len(selections) == 0 {
				// No remote policies would match this rule. Discard it.
				return nil
			}
			return &cilium.PortNetworkPolicyRule{
				RemotePolicies: selections.AsUint32Slice(),
			}
		}
	}

	// Get selections for each selector and count how many there are
	sels := make([][]uint32, 0, len(selectors))
	wildcardFound := false
	var count int
	for sel, l7 := range selectors {
		if sel.IsWildcard() {
			wildcardFound = true
			break
		}

		if l7.IsRedirect() {
			// Issue a warning if this port-0 rule is a redirect.
			// Deny rules don't support L7 therefore for the deny case
			// l7.IsRedirect() will always return false.
			log.Warningf("L3-only rule for selector %v surprisingly requires proxy redirection (%v)!", sel, *l7)
		}

		selections := sel.GetSelections()
		if len(selections) == 0 {
			continue
		}
		count += len(selections)
		sels = append(sels, selections.AsUint32Slice())
	}

	var remotePolicies []uint32

	if wildcardFound {
		// Optimize the policy if the endpoint selector is a wildcard by
		// keeping remote policies list empty to match all remote policies.
	} else if count == 0 {
		// No remote policies would match this rule. Discard it.
		return nil
	} else {
		// allocate slice and copy selected identities
		remotePolicies = make([]uint32, 0, count)
		for _, selections := range sels {
			remotePolicies = append(remotePolicies, selections...)
		}
		slices.Sort(remotePolicies)
		remotePolicies = slices.Compact(remotePolicies)
	}
	return &cilium.PortNetworkPolicyRule{
		RemotePolicies: remotePolicies,
	}
}

func getDirectionNetworkPolicy(ep endpoint.EndpointUpdater, l4Policy policy.L4PolicyMap, policyEnforced bool, useFullTLSContext bool, vis policy.DirectionalVisibilityPolicy, dir string) []*cilium.PortNetworkPolicy {
	// TODO: integrate visibility with enforced policy
	if !policyEnforced {
		PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, len(vis)+1)
		// Always allow all ports
		PerPortPolicies = append(PerPortPolicies, allowAllTCPPortNetworkPolicy)
		for _, visMeta := range vis {
			// Set up rule with 'L7Proto' as needed for proxylib parsers
			if visMeta.Proto == u8proto.TCP && visMeta.Parser != policy.ParserTypeHTTP && visMeta.Parser != policy.ParserTypeDNS {
				PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
					Port:     uint32(visMeta.Port),
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{
						{
							L7Proto: visMeta.Parser.String(),
						},
					},
				})
			}
		}
		return SortPortNetworkPolicies(PerPortPolicies)
	}

	if l4Policy == nil || l4Policy.Len() == 0 {
		return nil
	}

	PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, l4Policy.Len())
	l4Policy.ForEach(func(l4 *policy.L4Filter) bool {
		var protocol envoy_config_core.SocketAddress_Protocol
		switch l4.U8Proto {
		case u8proto.TCP, u8proto.ANY:
			protocol = envoy_config_core.SocketAddress_TCP
		default:
			// Other protocol rules not sent to Envoy for now.
			return true
		}

		port := l4.Port
		if port == 0 && l4.PortName != "" {
			port = ep.GetNamedPort(l4.Ingress, l4.PortName, l4.U8Proto)
			if port == 0 {
				return true // Skip if a named port can not be resolved (yet)
			}
		}

		rules := make([]*cilium.PortNetworkPolicyRule, 0, len(l4.PerSelectorPolicies))
		allowAll := false

		// Assume none of the rules have side-effects so that rule evaluation can
		// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
		// is set to 'false' below if any rules with side effects are encountered,
		// causing all the applicable rules to be evaluated instead.
		canShortCircuit := true

		if port == 0 {
			// L3-only rule, must generate L7 allow-all in case there are other
			// port-specific rules. Otherwise traffic from allowed remotes could be dropped.
			rule := getWildcardNetworkPolicyRule(l4.PerSelectorPolicies)
			if rule != nil {
				log.WithFields(logrus.Fields{
					logfields.EndpointID:       ep.GetID(),
					logfields.TrafficDirection: dir,
					logfields.Port:             port,
					logfields.PolicyID:         rule.RemotePolicies,
				}).Debug("Wildcard PortNetworkPolicyRule matching remote IDs")

				if len(rule.RemotePolicies) == 0 {
					// Got an allow-all rule, which can short-circuit all of
					// the other rules.
					allowAll = true
				}
				rules = append(rules, rule)
			}
		} else {
			nSelectors := len(l4.PerSelectorPolicies)
			for sel, l7 := range l4.PerSelectorPolicies {
				// A single selector is effectively a wildcard, as bpf passes through
				// only allowed l3. If there are multiple selectors for this l4-filter
				// then the proxy may need to drop some allowed l3 due to l7 rules potentially
				// being different between the selectors.
				wildcard := nSelectors == 1 || sel.IsWildcard()
				rule, cs := getPortNetworkPolicyRule(sel, wildcard, l4.L7Parser, l7, useFullTLSContext)
				if rule != nil {
					if !cs {
						canShortCircuit = false
					}

					log.WithFields(logrus.Fields{
						logfields.EndpointID:       ep.GetID(),
						logfields.TrafficDirection: dir,
						logfields.Port:             port,
						logfields.PolicyID:         rule.RemotePolicies,
						logfields.ServerNames:      rule.ServerNames,
					}).Debug("PortNetworkPolicyRule matching remote IDs")

					if len(rule.RemotePolicies) == 0 && rule.L7 == nil && rule.DownstreamTlsContext == nil && rule.UpstreamTlsContext == nil && len(rule.ServerNames) == 0 {
						// Got an allow-all rule, which can short-circuit all of
						// the other rules.
						allowAll = true
					}
					rules = append(rules, rule)
				}
			}
		}
		// Short-circuit rules if a rule allows all and all other rules can be short-circuited
		if allowAll && canShortCircuit {
			log.Debug("Short circuiting HTTP rules due to rule allowing all and no other rules needing attention")
			rules = nil
		}

		// No rule for this port matches any remote identity.
		// This means that no traffic was explicitly allowed for this port.
		// In this case, just don't generate any PortNetworkPolicy for this
		// port.
		if !allowAll && len(rules) == 0 {
			return true
		}

		// NPDS supports port ranges.
		PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
			Port:     uint32(port),
			EndPort:  uint32(l4.EndPort),
			Protocol: protocol,
			Rules:    SortPortNetworkPolicyRules(rules),
		})
		return true
	})

	if len(PerPortPolicies) == 0 {
		return nil
	}

	return SortPortNetworkPolicies(PerPortPolicies)
}

// getNetworkPolicy converts a network policy into a cilium.NetworkPolicy.
func getNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, ips []string, l4Policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext bool,
) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		EndpointIps:      ips,
		EndpointId:       ep.GetID(),
		ConntrackMapName: ep.ConntrackNameLocked(),
	}

	var visIngress policy.DirectionalVisibilityPolicy
	var visEgress policy.DirectionalVisibilityPolicy
	if vis != nil {
		visIngress = vis.Ingress
		visEgress = vis.Egress
	}
	var ingressMap policy.L4PolicyMap
	var egressMap policy.L4PolicyMap
	if l4Policy != nil {
		ingressMap = l4Policy.Ingress.PortRules
		egressMap = l4Policy.Egress.PortRules
	}
	p.IngressPerPortPolicies = getDirectionNetworkPolicy(ep, ingressMap, ingressPolicyEnforced, useFullTLSContext, visIngress, "ingress")
	p.EgressPerPortPolicies = getDirectionNetworkPolicy(ep, egressMap, egressPolicyEnforced, useFullTLSContext, visEgress, "egress")

	return p
}

// return the Envoy proxy node IDs that need to ACK the policy.
func getNodeIDs(ep endpoint.EndpointUpdater, policy *policy.L4Policy) []string {
	nodeIDs := make([]string, 0, 1)

	// Host proxy uses "127.0.0.1" as the nodeID
	nodeIDs = append(nodeIDs, "127.0.0.1")
	// Require additional ACK from proxylib if policy has proxylib redirects
	// Note that if a previous policy had a proxylib redirect and this one does not,
	// we only wait for the ACK from the main Envoy node ID.
	if policy.HasProxylibRedirect() {
		// Proxylib uses "127.0.0.2" as the nodeID
		nodeIDs = append(nodeIDs, "127.0.0.2")
	}
	return nodeIDs
}

func (s *xdsServer) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup,
) (error, func() error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var ips []string
	if ipv6 := ep.GetIPv6Address(); ipv6 != "" {
		ips = append(ips, ipv6)
	}
	if ipv4 := ep.GetIPv4Address(); ipv4 != "" {
		ips = append(ips, ipv4)
	}
	if len(ips) == 0 {
		// It looks like the "host EP" (identity == 1) has no IPs, so it is possible to find
		// there are no IPs here. In this case just skip without updating a policy, as
		// policies are always keyed by an IP.
		//
		// TODO: When L7 policy support for the host is needed, all host IPs should be
		// considered here?
		log.WithField(logfields.EndpointID, ep.GetID()).Debug("Endpoint has no IP addresses")
		return nil, func() error { return nil }
	}

	networkPolicy := getNetworkPolicy(ep, vis, ips, policy, ingressPolicyEnforced, egressPolicyEnforced, s.config.useFullTLSContext)

	// First, validate the policy
	err := networkPolicy.Validate()
	if err != nil {
		return fmt.Errorf("error validating generated NetworkPolicy for Endpoint %d: %w", ep.GetID(), err), nil
	}

	nodeIDs := getNodeIDs(ep, policy)

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if s.proxyListeners == 0 {
		wg = nil
	}

	// When successful, push policy into the cache.
	var callback func(error)
	if policy != nil {
		policyRevision := policy.Revision
		callback = func(err error) {
			if err == nil {
				go ep.OnProxyPolicyUpdate(policyRevision)
			}
		}
	}
	epID := ep.GetID()
	resourceName := strconv.FormatUint(epID, 10)
	revertFunc := s.NetworkPolicyMutator.Upsert(NetworkPolicyTypeURL, resourceName, networkPolicy, nodeIDs, wg, callback)
	revertUpdatedNetworkPolicyEndpoints := make(map[string]endpoint.EndpointUpdater, len(ips))
	for _, ip := range ips {
		revertUpdatedNetworkPolicyEndpoints[ip] = s.localEndpointStore.getLocalEndpoint(ip)
		s.localEndpointStore.setLocalEndpoint(ip, ep)
	}

	return nil, func() error {
		log.Debug("Reverting xDS network policy update")

		s.mutex.Lock()
		defer s.mutex.Unlock()

		for ip, ep := range revertUpdatedNetworkPolicyEndpoints {
			if ep == nil {
				s.localEndpointStore.removeLocalEndpoint(ip)
			} else {
				s.localEndpointStore.setLocalEndpoint(ip, ep)
			}
		}

		// Don't wait for an ACK for the reverted xDS updates.
		// This is best-effort.
		revertFunc(nil)

		log.Debug("Finished reverting xDS network policy update")

		return nil
	}
}

func (s *xdsServer) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	epID := ep.GetID()
	resourceName := strconv.FormatUint(epID, 10)
	s.networkPolicyCache.Delete(NetworkPolicyTypeURL, resourceName)

	ip := ep.GetIPv6Address()
	if ip != "" {
		s.localEndpointStore.removeLocalEndpoint(ip)
	}
	ip = ep.GetIPv4Address()
	if ip != "" {
		s.localEndpointStore.removeLocalEndpoint(ip)
		// Delete node resources held in the cache for the endpoint
		s.NetworkPolicyMutator.DeleteNode(ip)
	}
}

func (s *xdsServer) RemoveAllNetworkPolicies() {
	s.networkPolicyCache.Clear(NetworkPolicyTypeURL)
}

func (s *xdsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	resources, err := s.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, "", resourceNames)
	if err != nil {
		return nil, err
	}
	networkPolicies := make(map[string]*cilium.NetworkPolicy, len(resources.Resources))
	for _, res := range resources.Resources {
		networkPolicy := res.(*cilium.NetworkPolicy)
		for _, ip := range networkPolicy.EndpointIps {
			networkPolicies[ip] = networkPolicy
		}
	}
	return networkPolicies, nil
}

// Resources contains all Envoy resources parsed from a CiliumEnvoyConfig CRD
type Resources struct {
	Listeners []*envoy_config_listener.Listener
	Secrets   []*envoy_config_tls.Secret
	Routes    []*envoy_config_route.RouteConfiguration
	Clusters  []*envoy_config_cluster.Cluster
	Endpoints []*envoy_config_endpoint.ClusterLoadAssignment

	// Callback functions that are called if the corresponding Listener change was successfully acked by Envoy
	PortAllocationCallbacks map[string]func(context.Context) error
}

// ListenersAddedOrDeleted returns 'true' if a listener is added or removed when updating from 'old'
// to 'new'
func (old *Resources) ListenersAddedOrDeleted(new *Resources) bool {
	// Typically the number of listeners in a CEC is small (e.g, one), so it should be OK to
	// scan the slices like here
	for _, nl := range new.Listeners {
		found := false
		for _, ol := range old.Listeners {
			if ol.Name == nl.Name {
				found = true
				break
			}
		}
		if !found {
			return true // a listener was added
		}
	}
	for _, ol := range old.Listeners {
		found := false
		for _, nl := range new.Listeners {
			if nl.Name == ol.Name {
				found = true
				break
			}
		}
		if !found {
			return true // a listener was removed
		}
	}
	return false
}

func (s *xdsServer) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	if option.Config.Debug {
		msg := ""
		sep := ""
		if len(resources.Listeners) > 0 {
			msg += fmt.Sprintf("%d listeners", len(resources.Listeners))
			sep = ", "
		}
		if len(resources.Routes) > 0 {
			msg += fmt.Sprintf("%s%d routes", sep, len(resources.Routes))
			sep = ", "
		}
		if len(resources.Clusters) > 0 {
			msg += fmt.Sprintf("%s%d clusters", sep, len(resources.Clusters))
			sep = ", "
		}
		if len(resources.Endpoints) > 0 {
			msg += fmt.Sprintf("%s%d endpoints", sep, len(resources.Endpoints))
			sep = ", "
		}
		if len(resources.Secrets) > 0 {
			msg += fmt.Sprintf("%s%d secrets", sep, len(resources.Secrets))
		}

		log.Debugf("UpsertEnvoyResources: Upserting %s...", msg)
	}
	var wg *completion.WaitGroup
	// Listener config may fail if it refers to a cluster that has not been added yet, so we
	// must wait for Envoy to ACK cluster config before adding Listeners to be sure Listener
	// config does not fail for this reason.
	// Enable wait before new Listeners are added if clusters are also added.
	if len(resources.Listeners) > 0 && len(resources.Clusters) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Do not wait for the addition of routes, clusters, endpoints, routes,
	// or secrets as there are no guarantees that these additions will be
	// acked. For example, if the listener referring to was already deleted
	// earlier, there are no references to the deleted resources anymore,
	// in which case we could wait forever for the ACKs. This could also
	// happen if there is no listener referring to these named
	// resources to begin with.
	// If both listeners and clusters are added then wait for clusters.
	for _, r := range resources.Secrets {
		log.Debugf("Envoy upsertSecret %s", r.Name)
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, nil, nil))
	}
	for _, r := range resources.Endpoints {
		log.Debugf("Envoy upsertEndpoint %s %v", r.ClusterName, r)
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, nil, nil))
	}
	for _, r := range resources.Clusters {
		log.Debugf("Envoy upsertCluster %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg, nil))
	}
	for _, r := range resources.Routes {
		log.Debugf("Envoy upsertRoute %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, nil, nil))
	}
	// Wait before new Listeners are added if clusters were also added above.
	if wg != nil {
		start := time.Now()
		log.Debug("UpsertEnvoyResources: Waiting for cluster updates to complete...")
		err := wg.Wait()
		log.Debugf("UpsertEnvoyResources: Wait time for cluster updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
			return err
		}
		wg = nil
	}
	// Wait only if new Listeners are added, as they will always be acked.
	// (unreferenced routes or endpoints (and maybe clusters) are not ACKed or NACKed).
	if len(resources.Listeners) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	for _, r := range resources.Listeners {
		log.Debugf("Envoy upsertListener %s %v", r.Name, r)
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg,
			// this callback is not called if there is no change
			func(err error) {
				if err == nil && resources.PortAllocationCallbacks[listenerName] != nil {
					if callbackErr := resources.PortAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}
	if wg != nil {
		start := time.Now()
		log.Debug("UpsertEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		log.Debugf("UpsertEnvoyResources: Wait time for proxy updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

func (s *xdsServer) UpdateEnvoyResources(ctx context.Context, old, new Resources) error {
	waitForDelete := false
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Wait only if new Listeners are added, as they will always be acked.
	// (unreferenced routes or endpoints (and maybe clusters) are not ACKed or NACKed).
	if len(new.Listeners) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	// Delete old listeners not added in 'new' or if old and new listener have different ports
	var deleteListeners []*envoy_config_listener.Listener
	for _, oldListener := range old.Listeners {
		found := false
		port := uint32(0)
		if addr := oldListener.Address.GetSocketAddress(); addr != nil {
			port = addr.GetPortValue()
		}
		for _, newListener := range new.Listeners {
			if newListener.Name == oldListener.Name {
				if addr := newListener.Address.GetSocketAddress(); addr != nil && addr.GetPortValue() != port {
					log.Debugf("UpdateEnvoyResources: %s port changing from %d to %d...", newListener.Name, port, addr.GetPortValue())
					waitForDelete = true
				} else {
					// port is not changing, remove from new.PortAllocations to prevent acking an already acked port.
					delete(new.PortAllocationCallbacks, newListener.Name)
					found = true
				}
				break
			}
		}
		if !found {
			deleteListeners = append(deleteListeners, oldListener)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d listeners...", len(deleteListeners), len(new.Listeners))
	for _, listener := range deleteListeners {
		listenerName := listener.Name
		revertFuncs = append(revertFuncs, s.deleteListener(listener.Name, wg,
			func(err error) {
				if err == nil && old.PortAllocationCallbacks[listenerName] != nil {
					if callbackErr := old.PortAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}

	// Do not wait for the deletion of routes, clusters, endpoints, or
	// secrets as there are no quarantees that these deletions will be
	// acked. For example, if the listener referring to was already deleted
	// earlier, there are no references to the deleted resources any more,
	// in which case we could wait forever for the ACKs. This could also
	// happen if there is no listener referring to these other named
	// resources to begin with.

	// Delete old routes not added in 'new'
	var deleteRoutes []*envoy_config_route.RouteConfiguration
	for _, oldRoute := range old.Routes {
		found := false
		for _, newRoute := range new.Routes {
			if newRoute.Name == oldRoute.Name {
				found = true
			}
		}
		if !found {
			deleteRoutes = append(deleteRoutes, oldRoute)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d routes...", len(deleteRoutes), len(new.Routes))
	for _, route := range deleteRoutes {
		revertFuncs = append(revertFuncs, s.deleteRoute(route.Name, nil, nil))
	}

	// Delete old clusters not added in 'new'
	var deleteClusters []*envoy_config_cluster.Cluster
	for _, oldCluster := range old.Clusters {
		found := false
		for _, newCluster := range new.Clusters {
			if newCluster.Name == oldCluster.Name {
				found = true
			}
		}
		if !found {
			deleteClusters = append(deleteClusters, oldCluster)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d clusters...", len(deleteClusters), len(new.Clusters))
	for _, cluster := range deleteClusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(cluster.Name, nil, nil))
	}

	// Delete old endpoints not added in 'new'
	var deleteEndpoints []*envoy_config_endpoint.ClusterLoadAssignment
	for _, oldEndpoint := range old.Endpoints {
		found := false
		for _, newEndpoint := range new.Endpoints {
			if newEndpoint.ClusterName == oldEndpoint.ClusterName {
				found = true
			}
		}
		if !found {
			deleteEndpoints = append(deleteEndpoints, oldEndpoint)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d endpoints...", len(deleteEndpoints), len(new.Endpoints))
	for _, endpoint := range deleteEndpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(endpoint.ClusterName, nil, nil))
	}

	// Delete old secrets not added in 'new'
	var deleteSecrets []*envoy_config_tls.Secret
	for _, oldSecret := range old.Secrets {
		found := false
		for _, newSecret := range new.Secrets {
			if newSecret.Name == oldSecret.Name {
				found = true
			}
		}
		if !found {
			deleteSecrets = append(deleteSecrets, oldSecret)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d secrets...", len(deleteSecrets), len(new.Secrets))
	for _, secret := range deleteSecrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(secret.Name, nil, nil))
	}

	// Have to wait for deletes to complete before adding new listeners if a listener's port number is changed.
	if wg != nil && waitForDelete {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for proxy deletes to complete...")
		err := wg.Wait()
		if err != nil {
			log.Debug("UpdateEnvoyResources: delete failed: ", err)
		}
		log.Debug("UpdateEnvoyResources: Wait time for proxy deletes: ", time.Since(start))
		// new wait group for adds
		wg = completion.NewWaitGroup(ctx)
	}

	// Add new Secrets
	for _, r := range new.Secrets {
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, nil, nil))
	}
	// Add new Endpoints
	for _, r := range new.Endpoints {
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, nil, nil))
	}
	// Add new Clusters
	for _, r := range new.Clusters {
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg, nil))
	}
	// Add new Routes
	for _, r := range new.Routes {
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, nil, nil))
	}
	if wg != nil && len(new.Clusters) > 0 {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for cluster updates to complete...")
		err := wg.Wait()
		if err != nil {
			log.Debug("UpdateEnvoyResources: cluster update failed: ", err)
		}
		log.Debug("UpdateEnvoyResources: Wait time for cluster updates: ", time.Since(start))
		// new wait group for adds
		wg = completion.NewWaitGroup(ctx)
	}
	// Add new Listeners
	for _, r := range new.Listeners {
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg,
			// this callback is not called if there is no change
			func(err error) {
				if err == nil && new.PortAllocationCallbacks[listenerName] != nil {
					if callbackErr := new.PortAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}

	if wg != nil {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		log.Debugf("UpdateEnvoyResources: Wait time for proxy updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("UpdateEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

func (s *xdsServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	log.Debugf("DeleteEnvoyResources: Deleting %d listeners, %d routes, %d clusters, %d endpoints, and %d secrets...",
		len(resources.Listeners), len(resources.Routes), len(resources.Clusters), len(resources.Endpoints), len(resources.Secrets))
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Wait only if new Listeners are added, as they will always be acked.
	// (unreferenced routes or endpoints (and maybe clusters) are not ACKed or NACKed).
	if len(resources.Listeners) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	for _, r := range resources.Listeners {
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.deleteListener(r.Name, wg,
			func(err error) {
				if err == nil && resources.PortAllocationCallbacks[listenerName] != nil {
					if callbackErr := resources.PortAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}

	// Do not wait for the deletion of routes, clusters, or endpoints, as
	// there are no guarantees that these deletions will be acked. For
	// example, if the listener referring to was already deleted earlier,
	// there are no references to the deleted resources anymore, in which
	// case we could wait forever for the ACKs. This could also happen if
	// there is no listener referring to other named resources to
	// begin with.
	for _, r := range resources.Routes {
		revertFuncs = append(revertFuncs, s.deleteRoute(r.Name, nil, nil))
	}
	for _, r := range resources.Clusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(r.Name, nil, nil))
	}
	for _, r := range resources.Endpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(r.ClusterName, nil, nil))
	}
	for _, r := range resources.Secrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(r.Name, nil, nil))
	}

	if wg != nil {
		start := time.Now()
		log.Debug("DeleteEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		log.Debugf("DeleteEnvoyResources: Wait time for proxy updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("DeleteEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}
