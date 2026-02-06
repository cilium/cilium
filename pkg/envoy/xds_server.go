// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	envoy_mysql_proxy "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/network/mysql_proxy/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_upstream_codec "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/upstream_codec/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_mongo_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/mongo_proxy/v3"
	envoy_config_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	_ "github.com/cilium/cilium/pkg/envoy/resource"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
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

// XDSServer provides a high-lever interface to manage resources published using the xDS gRPC API.
type XDSServer interface {
	// AddListener adds a listener to a running Envoy proxy.
	AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error
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
	// UseCurrentNetworkPolicy waits for any pending update on NetworkPolicy to be acked.
	UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup)
	// UpdateNetworkPolicy adds or updates a network policy in the set published to L7 proxies.
	// When the proxy acknowledges the network policy update, it will result in
	// a subsequent call to the endpoint's OnProxyPolicyUpdate() function.
	UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, func() error)
	// RemoveNetworkPolicy removes network policies relevant to the specified
	// endpoint from the set published to L7 proxies, and stops listening for
	// acks for policies on this endpoint.
	RemoveNetworkPolicy(ep endpoint.EndpointInfoSource)
	// RemoveAllNetworkPolicies removes all network policies from the set published
	// to L7 proxies.
	RemoveAllNetworkPolicies()
}

type xdsServer struct {
	logger *slog.Logger

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

	// listenerCount is the set of names of listeners that have been added by
	// calling AddListener.
	// mutex must be held when accessing this.
	// Value holds the number of redirects using the listener named by the key.
	listenerCount map[string]uint

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

	resourceConfig map[string]*xds.ResourceTypeConfiguration

	// stopFunc contains the function which stops the xDS gRPC server.
	stopFunc context.CancelFunc

	// IPCache is used for tracking IP->Identity mappings and propagating
	// them to the proxy via NPHDS in the cases described
	ipCache IPCacheEventSource

	restorerPromise promise.Promise[endpointstate.Restorer]

	localEndpointStore *LocalEndpointStore

	l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator
	secretManager     certificatemanager.SecretManager
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
	httpStreamIdleTimeout         int
	useFullTLSContext             bool
	useSDS                        bool
	proxyXffNumTrustedHopsIngress uint32
	proxyXffNumTrustedHopsEgress  uint32
	policyRestoreTimeout          time.Duration
	metrics                       xds.Metrics
	httpLingerConfig              int
}

// newXDSServer creates a new xDS GRPC server.
func newXDSServer(logger *slog.Logger, restorerPromise promise.Promise[endpointstate.Restorer], ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager) *xdsServer {
	xdsServer := &xdsServer{
		logger:             logger,
		restorerPromise:    restorerPromise,
		listenerCount:      make(map[string]uint),
		ipCache:            ipCache,
		localEndpointStore: localEndpointStore,

		socketPath:    getXDSSocketPath(config.envoySocketDir),
		accessLogPath: getAccessLogSocketPath(config.envoySocketDir),
		config:        config,
		secretManager: secretManager,
	}

	xdsServer.initializeXdsConfigs()

	return xdsServer
}

func (s *xdsServer) start(ctx context.Context) error {
	return s.startXDSGRPCServer(ctx, s.resourceConfig)
}

func (s *xdsServer) initializeXdsConfigs() {
	ldsCache := xds.NewCache(s.logger)
	ldsMutator := xds.NewAckingResourceMutatorWrapper(s.logger, ldsCache, s.config.metrics)
	ldsConfig := &xds.ResourceTypeConfiguration{
		Source:      ldsCache,
		AckObserver: ldsMutator,
	}

	rdsCache := xds.NewCache(s.logger)
	rdsMutator := xds.NewAckingResourceMutatorWrapper(s.logger, rdsCache, s.config.metrics)
	rdsConfig := &xds.ResourceTypeConfiguration{
		Source:      rdsCache,
		AckObserver: rdsMutator,
	}

	cdsCache := xds.NewCache(s.logger)
	cdsMutator := xds.NewAckingResourceMutatorWrapper(s.logger, cdsCache, s.config.metrics)
	cdsConfig := &xds.ResourceTypeConfiguration{
		Source:      cdsCache,
		AckObserver: cdsMutator,
	}

	edsCache := xds.NewCache(s.logger)
	edsMutator := xds.NewAckingResourceMutatorWrapper(s.logger, edsCache, s.config.metrics)
	edsConfig := &xds.ResourceTypeConfiguration{
		Source:      edsCache,
		AckObserver: edsMutator,
	}

	sdsCache := xds.NewCache(s.logger)
	sdsMutator := xds.NewAckingResourceMutatorWrapper(s.logger, sdsCache, s.config.metrics)
	sdsConfig := &xds.ResourceTypeConfiguration{
		Source:      sdsCache,
		AckObserver: sdsMutator,
	}

	npdsCache := xds.NewCache(s.logger)
	npdsMutator := xds.NewAckingResourceMutatorWrapper(s.logger, npdsCache, s.config.metrics)
	npdsConfig := &xds.ResourceTypeConfiguration{
		Source:      npdsCache,
		AckObserver: npdsMutator,
	}

	nphdsCache := newNPHDSCache(s.logger, s.ipCache)
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

	s.resourceConfig = map[string]*xds.ResourceTypeConfiguration{
		ListenerTypeURL:           ldsConfig,
		RouteTypeURL:              rdsConfig,
		ClusterTypeURL:            cdsConfig,
		EndpointTypeURL:           edsConfig,
		SecretTypeURL:             sdsConfig,
		NetworkPolicyTypeURL:      npdsConfig,
		NetworkPolicyHostsTypeURL: nphdsConfig,
	}
}

func (s *xdsServer) newSocketListener() (*net.UnixListener, error) {
	// Make sure sockets dir exists
	socketsDir, _ := filepath.Split(s.socketPath)
	os.MkdirAll(GetSocketDir(socketsDir), 0o777)

	// Remove/Unlink the old unix domain socket, if any.
	_ = os.Remove(s.socketPath)

	socketListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("failed to open xDS listen socket at %s: %w", s.socketPath, err)
	}

	// Make the socket accessible by owner and group only.
	if err = os.Chmod(s.socketPath, 0o660); err != nil {
		return nil, fmt.Errorf("failed to change mode of xDS listen socket at %s: %w", s.socketPath, err)
	}
	// Change the group to ProxyGID allowing access from any process from that group.
	if err = os.Chown(s.socketPath, -1, s.config.proxyGID); err != nil {
		s.logger.Warn("Envoy: Failed to change the group of xDS listen socket",
			logfields.Path, s.socketPath,
			logfields.Error, err,
		)
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
	requestTimeout := int64(s.config.httpRequestTimeout)       // seconds
	idleTimeout := int64(s.config.httpIdleTimeout)             // seconds
	maxGRPCTimeout := int64(s.config.httpMaxGRPCTimeout)       // seconds
	streamIdleTimeout := int64(s.config.httpStreamIdleTimeout) // seconds
	numRetries := uint32(s.config.httpRetryCount)
	retryTimeout := int64(s.config.httpRetryTimeout) // seconds
	xffNumTrustedHops := s.config.proxyXffNumTrustedHopsEgress
	if isIngress {
		xffNumTrustedHops = s.config.proxyXffNumTrustedHopsIngress
	}

	hcmConfig := &envoy_config_http.HttpConnectionManager{
		StatPrefix: "proxy",
		UpgradeConfigs: []*envoy_config_http.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		},
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
		InternalAddressConfig: &envoy_config_http.HttpConnectionManager_InternalAddressConfig{
			UnixSockets: false,
			CidrRanges:  GetInternalListenerCIDRs(option.Config.IPv4Enabled(), option.Config.IPv6Enabled()),
		},
		StreamIdleTimeout: &durationpb.Duration{Seconds: streamIdleTimeout}, // 0 == disabled
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
	var ciliumConfig = &cilium.NetworkFilter{
		AccessLogPath: s.accessLogPath,
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
	s.logger.Debug("Envoy: AddAdminListener",
		logfields.Port, port,
	)

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
			InternalAddressConfig: &envoy_config_http.HttpConnectionManager_InternalAddressConfig{
				UnixSockets: false,
				// only RFC1918 IP addresses will be considered internal
				// https://datatracker.ietf.org/doc/html/rfc1918
				CidrRanges: GetInternalListenerCIDRs(option.Config.IPv4Enabled(), option.Config.IPv6Enabled()),
			},
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
			s.logger.Debug("Envoy: Adding admin listener failed",
				logfields.Port, port,
				logfields.Error, err,
			)
			// Remove the added listener in case of a failure
			s.removeListener(adminListenerName, nil, false)
		} else {
			s.logger.Info("Envoy: Listening for Admin API",
				logfields.Port, port,
			)
		}
	}, false)
}

func GetInternalListenerCIDRs(ipv4, ipv6 bool) []*envoy_config_core.CidrRange {
	var cidrRanges []*envoy_config_core.CidrRange

	if ipv4 {
		cidrRanges = append(cidrRanges,
			[]*envoy_config_core.CidrRange{
				{AddressPrefix: "10.0.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 8}},
				{AddressPrefix: "172.16.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 12}},
				{AddressPrefix: "192.168.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 16}},
				{AddressPrefix: "127.0.0.1", PrefixLen: &wrapperspb.UInt32Value{Value: 32}},
			}...)
	}

	if ipv6 {
		cidrRanges = append(cidrRanges, &envoy_config_core.CidrRange{
			AddressPrefix: "::1",
			PrefixLen:     &wrapperspb.UInt32Value{Value: 128},
		})
	}
	return cidrRanges
}

func (s *xdsServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	s.logger.Debug("Envoy: AddMetricsListener",
		logfields.Port, port,
	)

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
			InternalAddressConfig: &envoy_config_http.HttpConnectionManager_InternalAddressConfig{
				UnixSockets: false,
				// only RFC1918 IP addresses will be considered internal
				// https://datatracker.ietf.org/doc/html/rfc1918
				CidrRanges: GetInternalListenerCIDRs(option.Config.IPv4Enabled(), option.Config.IPv6Enabled()),
			},
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
			s.logger.Debug("Envoy: Adding metrics listener failed",
				logfields.Port, port,
				logfields.Error, err,
			)
			// Remove the added listener in case of a failure
			s.removeListener(metricsListenerName, nil, false)
		} else {
			s.logger.Info("Envoy: Listening for prometheus metrics",
				logfields.Port, port,
			)
		}
	}, false)
}

// addListener either reuses an existing listener with 'name', or creates a new one.
// 'listenerConf()' is only called if a new listener is being created.
func (s *xdsServer) addListener(name string, listenerConf func() *envoy_config_listener.Listener, wg *completion.WaitGroup, cb func(err error), isProxyListener bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	listenerConfig := listenerConf()
	if option.Config.EnableBPFTProxy {
		// Envoy since 1.20.0 uses SO_REUSEPORT on listeners by default.
		// BPF TPROXY is currently not compatible with SO_REUSEPORT, so disable it.
		// Note that this may degrade Envoy performance.
		listenerConfig.EnableReusePort = &wrapperspb.BoolValue{Value: false}
	}
	if err := listenerConfig.Validate(); err != nil {
		return fmt.Errorf("Envoy: Could not validate Listener %s: %w", listenerConfig.String(), err)
	}

	count := s.listenerCount[name]
	if count == 0 {
		if isProxyListener {
			s.proxyListeners++
		}
		s.logger.Info("Envoy: Upserting new listener",
			logfields.Listener, name,
		)
	}
	count++
	s.listenerCount[name] = count

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConfig, []string{"127.0.0.1"}, wg,
		func(err error) {
			if cb != nil {
				cb(err)
			}
		})
	return nil
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
func (s *xdsServer) upsertRoute(name string, conf *envoy_config_route.RouteConfiguration, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.routeMutator.Upsert(RouteTypeURL, name, conf, []string{"127.0.0.1"}, wg, nil)
}

// deleteRoute deletes an RDS Route.
func (s *xdsServer) deleteRoute(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.routeMutator.Delete(RouteTypeURL, name, []string{"127.0.0.1"}, wg, nil)
}

// upsertCluster either updates an existing CDS cluster with 'name', or creates a new one.
func (s *xdsServer) upsertCluster(name string, conf *envoy_config_cluster.Cluster, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.clusterMutator.Upsert(ClusterTypeURL, name, conf, []string{"127.0.0.1"}, wg, nil)
}

// deleteCluster deletes an CDS cluster.
func (s *xdsServer) deleteCluster(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.clusterMutator.Delete(ClusterTypeURL, name, []string{"127.0.0.1"}, wg, nil)
}

// upsertEndpoint either updates an existing EDS endpoint with 'name', or creates a new one.
func (s *xdsServer) upsertEndpoint(name string, conf *envoy_config_endpoint.ClusterLoadAssignment, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.endpointMutator.Upsert(EndpointTypeURL, name, conf, []string{"127.0.0.1"}, wg, nil)
}

// deleteEndpoint deletes an EDS endpoint.
func (s *xdsServer) deleteEndpoint(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.endpointMutator.Delete(EndpointTypeURL, name, []string{"127.0.0.1"}, wg, nil)
}

// upsertSecret either updates an existing SDS secret with 'name', or creates a new one.
func (s *xdsServer) upsertSecret(name string, conf *envoy_config_tls.Secret, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.secretMutator.Upsert(SecretTypeURL, name, conf, []string{"127.0.0.1"}, wg, nil)
}

// deleteSecret deletes an SDS secret.
func (s *xdsServer) deleteSecret(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.secretMutator.Delete(SecretTypeURL, name, []string{"127.0.0.1"}, wg, nil)
}

func getListenerFilter(isIngress bool, useOriginalSourceAddr bool, proxyPort uint16, lingerConfig int) *envoy_config_listener.ListenerFilter {
	conf := &cilium.BpfMetadata{
		IsIngress:                isIngress,
		UseOriginalSourceAddress: useOriginalSourceAddr,
		BpfRoot:                  bpf.BPFFSRoot(),
		IsL7Lb:                   false,
		ProxyId:                  uint32(proxyPort),
		IpcacheName:              ipcache.Name,
	}

	if lingerConfig >= 0 {
		lingerTime := uint32(lingerConfig)
		conf.OriginalSourceSoLingerTime = &lingerTime
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
	lingerConfig := -1
	if kind == policy.ParserTypeHTTP {
		lingerConfig = s.config.httpLingerConfig
	}
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
			getListenerFilter(isIngress, mayUseOriginalSourceAddr, port, lingerConfig),
		},
	}

	// Add filter chains
	if kind == policy.ParserTypeHTTP {
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(clusterName, false, isIngress))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(tlsClusterName, true, isIngress))
	} else {
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

func (s *xdsServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	s.logger.Debug("Envoy: AddListener",
		logfields.L7ParserType, kind,
		logfields.Listener, name,
		logfields.MayUseOriginalSourceAddr, mayUseOriginalSourceAddr,
	)

	return s.addListener(name, func() *envoy_config_listener.Listener {
		return s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr)
	}, wg, cb, true)
}

func (s *xdsServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	return s.removeListener(name, wg, true)
}

// removeListener removes an existing Envoy Listener.
func (s *xdsServer) removeListener(name string, wg *completion.WaitGroup, isProxyListener bool) xds.AckingResourceMutatorRevertFunc {
	s.logger.Debug("Envoy: RemoveListener",
		logfields.Listener, name,
	)

	var listenerRevertFunc xds.AckingResourceMutatorRevertFunc

	s.mutex.Lock()
	count := s.listenerCount[name]
	if count > 0 {
		count--
		if count == 0 {
			if isProxyListener {
				s.proxyListeners--
			}
			delete(s.listenerCount, name)
			s.logger.Info("Envoy: Deleting listener",
				logfields.Listener, name,
			)
			listenerRevertFunc = s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg, nil)
		} else {
			s.listenerCount[name] = count
		}
	} else {
		// Bail out if this listener does not exist
		s.logger.Error("Envoy: Attempt to remove non-existent listener",
			logfields.Listener, name,
		)
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
		s.listenerCount[name] = s.listenerCount[name] + 1
		s.mutex.Unlock()
	}
}

func getL7Rules(l7Rules []api.PortRuleL7, l7Proto string) *cilium.L7NetworkPolicyRules {
	allowRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	denyRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	useEnvoyMetadataMatcher := strings.HasPrefix(l7Proto, "envoy.")

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
			maps.Copy(rule.Rule, l7)
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

var CiliumXDSConfigSource = &envoy_config_core.ConfigSource{
	InitialFetchTimeout: &durationpb.Duration{Seconds: 30},
	ResourceApiVersion:  envoy_config_core.ApiVersion_V3,
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

// toEnvoyOriginatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for originating TLS (i.e., verifying TLS connections from *outside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well, which can
// lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS, and so this method will
// return whatever is in the *policy.TLSContext.
func toEnvoyOriginatingTLSContext(tls *policy.TLSContext, policySecretsNamespace string, useSDS, useFullTLSContext bool) *cilium.TLSContext {
	if !tls.FromFile && useSDS && policySecretsNamespace != "" {
		// If values are not present in these fields, then we should be using SDS,
		// and Secret should be populated.
		if tls.Secret.String() != "/" {
			return &cilium.TLSContext{
				ValidationContextSdsSecret: namespacedNametoSyncedSDSSecretName(tls.Secret, policySecretsNamespace),
			}
		}
		// This code _should_ be unreachable, because NetworkPolicy input validation does not allow
		// the Secret fields to be empty, so panic.
		panic("SDS Policy secrets cannot be empty, this should not be possible, please log an issue")
	}

	// If we are not using a synchronized secret or are reading from file, useFullTLSContext
	// matters.
	if useFullTLSContext {
		return &cilium.TLSContext{
			CertificateChain: tls.CertificateChain,
			PrivateKey:       tls.PrivateKey,
			TrustedCa:        tls.TrustedCA,
		}
	}

	return &cilium.TLSContext{
		TrustedCa: tls.TrustedCA,
	}
}

// toEnvoyTerminatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for terminating TLS (i.e., providing a valid cert to clients *inside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well, which can
// lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS, and so this method will
// return whatever is in the *policy.TLSContext.
func toEnvoyTerminatingTLSContext(tls *policy.TLSContext, policySecretsNamespace string, useSDS, useFullTLSContext bool) *cilium.TLSContext {
	if !tls.FromFile && useSDS && policySecretsNamespace != "" {
		// If the values have been read from Kubernetes, then we should be using SDS,
		// and Secret should be populated.
		if tls.Secret.String() != "/" {
			return &cilium.TLSContext{
				TlsSdsSecret: namespacedNametoSyncedSDSSecretName(tls.Secret, policySecretsNamespace),
			}
		}
		// This code _should_ be unreachable, because NetworkPolicy input validation does not allow
		// the Secret fields to be empty, so panic.
		panic("SDS Policy secrets cannot be empty, this should not be possible, please log an issue")
	}

	// If we are not using a synchronized secret or are reading from file, useFullTLSContext
	// matters.
	if useFullTLSContext {
		return &cilium.TLSContext{
			CertificateChain: tls.CertificateChain,
			PrivateKey:       tls.PrivateKey,
			TrustedCa:        tls.TrustedCA,
		}
	}

	return &cilium.TLSContext{
		CertificateChain: tls.CertificateChain,
		PrivateKey:       tls.PrivateKey,
	}
}

func namespacedNametoSyncedSDSSecretName(namespacedName types.NamespacedName, policySecretsNamespace string) string {
	if policySecretsNamespace == "" {
		return fmt.Sprintf("%s/%s", namespacedName.Namespace, namespacedName.Name)
	}
	return fmt.Sprintf("%s/%s-%s", policySecretsNamespace, namespacedName.Namespace, namespacedName.Name)
}

func (s *xdsServer) getPortNetworkPolicyRule(ep endpoint.EndpointUpdater, selectors policy.SelectorSnapshot, sel policy.CachedSelector, l7Rules *policy.PerSelectorPolicy, useFullTLSContext, useSDS bool, policySecretsNamespace string) (*cilium.PortNetworkPolicyRule, bool) {
	r := &cilium.PortNetworkPolicyRule{
		Deny: l7Rules.IsDeny(),
	}

	wildcard := sel.IsWildcard()

	// Optimize the policy if the endpoint selector is a wildcard by
	// keeping remote policies list empty to match all remote policies.
	if !wildcard {
		selections := sel.GetSelectionsAt(selectors)

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

	// Deny rules never have L7 rules and can not be short-circuited (i.e., rule evaluation
	// after an allow rule must continue to find the possibly applicable deny rule).
	if l7Rules.IsDeny() {
		return r, false
	}

	// Pass redirect port as proxy ID if the rule has an explicit listener reference.
	// This makes this rule to be ignored on any listener that does not have a matching
	// proxy ID.
	if l7Rules.Listener != "" {
		r.ProxyId = uint32(ep.GetListenerProxyPort(l7Rules.Listener))
	}

	// If secret synchronization is disabled, policySecretsNamespace will be the empty string.
	//
	// In that case, useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well,
	// which can lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
	// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS.
	//
	// If secret synchronization is enabled, useFullTLSContext is unused, as SDS handling can handle Secrets with extra
	// keys correctly.
	if l7Rules.TerminatingTLS != nil {
		r.DownstreamTlsContext = toEnvoyTerminatingTLSContext(l7Rules.TerminatingTLS, policySecretsNamespace, useSDS, useFullTLSContext)
	}
	if l7Rules.OriginatingTLS != nil {
		r.UpstreamTlsContext = toEnvoyOriginatingTLSContext(l7Rules.OriginatingTLS, policySecretsNamespace, useSDS, useFullTLSContext)
	}

	if len(l7Rules.ServerNames) > 0 {
		r.ServerNames = make([]string, 0, len(l7Rules.ServerNames))
		for sni := range l7Rules.ServerNames {
			r.ServerNames = append(r.ServerNames, sni)
		}
		slices.Sort(r.ServerNames)
	}

	// Assume none of the rules have side-effects so that rule evaluation can
	// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
	// is set to 'false' below if any rules with side effects are encountered,
	// causing all the applicable rules to be evaluated instead.
	canShortCircuit := true
	switch l7Rules.L7Parser {
	case policy.ParserTypeHTTP:
		// 'r.L7' is an interface which must not be set to a typed 'nil',
		// so check if we have any rules
		if len(l7Rules.HTTP) > 0 {
			// Use L7 rules computed earlier?
			var httpRules *cilium.HttpNetworkPolicyRules
			if l7Rules.EnvoyHTTPRules() != nil {
				httpRules = l7Rules.EnvoyHTTPRules()
				canShortCircuit = l7Rules.CanShortCircuit()
			} else {
				httpRules, canShortCircuit = s.l7RulesTranslator.GetEnvoyHTTPRules(&l7Rules.L7Rules, "")
			}
			r.L7 = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: httpRules,
			}
		}

	case policy.ParserTypeKafka:
		// Kafka is implemented as an Envoy Go Extension
		if len(l7Rules.Kafka) > 0 {
			// L7 rules are not sorted
			r.L7Proto = l7Rules.L7Parser.String()
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
			r.L7Proto = l7Rules.L7Parser.String()
			r.L7 = &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: getL7Rules(l7Rules.L7, r.L7Proto),
			}
		}
	}

	return r, canShortCircuit
}

// getWildcardNetworkPolicyRules returns the rules for port 0, which
// will be considered after port-specific rules.
func (s *xdsServer) getWildcardNetworkPolicyRules(snapshot policy.SelectorSnapshot, selectors policy.L7DataMap) (rules []*cilium.PortNetworkPolicyRule) {
	// selections are pre-sorted, so sorting is only needed if merging selections from multiple selectors
	if len(selectors) == 1 {
		for sel, l7 := range selectors {
			if sel.IsWildcard() {
				return append(rules, &cilium.PortNetworkPolicyRule{
					Deny: l7.IsDeny(),
				})
			}
			selections := sel.GetSelectionsAt(snapshot)
			if len(selections) == 0 {
				// No remote policies would match this rule. Discard it.
				return nil
			}
			return append(rules, &cilium.PortNetworkPolicyRule{
				Deny:           l7.IsDeny(),
				RemotePolicies: selections.AsUint32Slice(),
			})
		}
	}

	// Get selections for each selector and count how many there are
	allowSlices := make([][]uint32, 0, len(selectors))
	denySlices := make([][]uint32, 0, len(selectors))
	wildcardAllowFound := false
	wildcardDenyFound := false
	var allowCount, denyCount int
	for sel, l7 := range selectors {
		if sel.IsWildcard() {
			if l7.IsDeny() {
				wildcardDenyFound = true
				break
			} else {
				wildcardAllowFound = true
			}
		}

		if l7.IsRedirect() {
			// Issue a warning if this port-0 rule is a redirect.
			// Deny rules don't support L7 therefore for the deny case
			// l7.IsRedirect() will always return false.
			s.logger.Warn("L3-only rule for selector surprisingly requires proxy redirection!", logfields.Selector, sel)
		}

		selections := sel.GetSelectionsAt(snapshot)
		if len(selections) == 0 {
			continue
		}
		if l7.IsDeny() {
			denyCount += len(selections)
			denySlices = append(denySlices, selections.AsUint32Slice())
		} else {
			allowCount += len(selections)
			allowSlices = append(allowSlices, selections.AsUint32Slice())
		}
	}

	if wildcardDenyFound {
		return append(rules, &cilium.PortNetworkPolicyRule{
			Deny: true,
		})
	}
	if len(denySlices) > 0 {
		// allocate slice and copy selected identities
		denies := make([]uint32, 0, denyCount)
		for _, selections := range denySlices {
			denies = append(denies, selections...)
		}
		slices.Sort(denies)
		denies = slices.Compact(denies)

		rules = append(rules, &cilium.PortNetworkPolicyRule{
			Deny:           true,
			RemotePolicies: denies,
		})
	}

	if wildcardAllowFound {
		rules = append(rules, &cilium.PortNetworkPolicyRule{})
	} else if len(allowSlices) > 0 {
		// allocate slice and copy selected identities
		allows := make([]uint32, 0, allowCount)
		for _, selections := range allowSlices {
			allows = append(allows, selections...)
		}
		slices.Sort(allows)
		allows = slices.Compact(allows)

		rules = append(rules, &cilium.PortNetworkPolicyRule{
			RemotePolicies: allows,
		})
	}

	return rules
}

func (s *xdsServer) getDirectionNetworkPolicy(ep endpoint.EndpointUpdater, selectors policy.SelectorSnapshot, l4Policy policy.L4PolicyMaps, policyEnforced bool, useFullTLSContext, useSDS bool, dir string, policySecretsNamespace string) []*cilium.PortNetworkPolicy {
	// TODO: integrate visibility with enforced policy
	if !policyEnforced {
		// Always allow all ports
		return []*cilium.PortNetworkPolicy{allowAllTCPPortNetworkPolicy}
	}

	if l4Policy == nil || l4Policy.Len() == 0 {
		return nil
	}

	PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, l4Policy.Len())
	wildcardAllowAll := false
	wildcardDenyAll := false

	// Check for wildcard port policy first
	addWildcardRules := func(l4 *policy.L4Filter) {
		if l4 == nil {
			return
		}

		wildcardRules := s.getWildcardNetworkPolicyRules(selectors, l4.PerSelectorPolicies)

		for _, rule := range wildcardRules {
			s.logger.Debug("Wildcard PortNetworkPolicyRule matching remote IDs",
				logfields.EndpointID, ep.GetID(),
				logfields.Version, selectors,
				logfields.TrafficDirection, dir,
				logfields.Port, "0",
				logfields.IsDeny, rule.Deny,
				logfields.PolicyID, rule.RemotePolicies,
			)

			if len(rule.RemotePolicies) == 0 {
				if rule.Deny {
					// Got an deny-all rule, which short-circuits all of
					// the other rules.
					wildcardDenyAll = true
				} else {
					// Got an allow-all rule, which can short-circuit all of
					// the other rules.
					wildcardAllowAll = true
				}
			}
		}

		if len(wildcardRules) > 0 {
			PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
				Port:     0,
				EndPort:  0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules:    envoypolicy.SortPortNetworkPolicyRules(wildcardRules),
			})
		} else {
			s.logger.Debug("Skipping wildcard PortNetworkPolicy due to no matching remote identities",
				logfields.EndpointID, ep.GetID(),
				logfields.TrafficDirection, dir,
				logfields.Port, "0",
			)
		}
	}

	for i := range l4Policy {
		addWildcardRules(l4Policy[i].ExactLookup("0", 0, u8proto.ANY.String()))
		addWildcardRules(l4Policy[i].ExactLookup("0", 0, u8proto.TCP.String()))
	}

	if !wildcardDenyAll {
		for l4 := range l4Policy.Filters() {
			var protocol envoy_config_core.SocketAddress_Protocol
			switch l4.U8Proto {
			case u8proto.TCP, u8proto.ANY:
				protocol = envoy_config_core.SocketAddress_TCP
			default:
				// Other protocol rules not sent to Envoy for now.
				continue
			}

			port := l4.Port
			if port == 0 && l4.PortName != "" {
				port = ep.GetNamedPort(l4.Ingress, l4.PortName, l4.U8Proto)
			}

			// Skip if a named port can not be resolved (yet)
			// wildcard port already taken care of above
			if port == 0 {
				continue
			}

			rules := make([]*cilium.PortNetworkPolicyRule, 0, len(l4.PerSelectorPolicies))

			// Assume none of the rules have side-effects so that rule evaluation can
			// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
			// is set to 'false' below if any rules with side effects are encountered,
			// causing all the applicable rules to be evaluated instead.
			// Also set to 'false' if any deny rules exist.
			canShortCircuit := true
			var allowAllRule *cilium.PortNetworkPolicyRule
			var denyAllRule *cilium.PortNetworkPolicyRule

			for sel, l7 := range l4.PerSelectorPolicies {
				rule, cs := s.getPortNetworkPolicyRule(ep, selectors, sel, l7, useFullTLSContext, useSDS, policySecretsNamespace)
				if rule != nil {
					if !cs {
						canShortCircuit = false
					}

					s.logger.Debug("PortNetworkPolicyRule matching remote IDs",
						logfields.EndpointID, ep.GetID(),
						logfields.Version, selectors,
						logfields.TrafficDirection, dir,
						logfields.Port, port,
						logfields.ProxyPort, rule.ProxyId,
						logfields.PolicyID, rule.RemotePolicies,
						logfields.ServerNames, rule.ServerNames,
					)

					if rule.Deny && len(rule.RemotePolicies) == 0 {
						// Got an deny-all rule, which short-circuits all of
						// the other rules on this port.
						denyAllRule = rule
						rules = []*cilium.PortNetworkPolicyRule{denyAllRule}
						break
					}

					if len(rule.RemotePolicies) == 0 && rule.L7 == nil && rule.DownstreamTlsContext == nil && rule.UpstreamTlsContext == nil && len(rule.ServerNames) == 0 && rule.ProxyId == 0 {
						// Got an allow-all rule, which can short-circuit all of
						// the other rules on this port.
						allowAllRule = rule
					}
					rules = append(rules, rule)
				}
			}

			// No rule for this port matches any remote identity.
			// In this case, just don't generate any PortNetworkPolicy for this
			// port.
			if len(rules) == 0 {
				s.logger.Debug("Skipping PortNetworkPolicy due to no matching remote identities",
					logfields.EndpointID, ep.GetID(),
					logfields.TrafficDirection, dir,
					logfields.Port, port,
				)
				continue
			}

			// Short-circuit rules if a rule allows all and all other rules can be short-circuited
			if denyAllRule == nil && canShortCircuit {
				if wildcardAllowAll {
					s.logger.Debug("Short circuiting HTTP rules due to wildcard allowing all and no other rules needing attention",
						logfields.EndpointID, ep.GetID(),
						logfields.TrafficDirection, dir,
						logfields.Port, port,
					)
					continue
				}
				if allowAllRule != nil {
					s.logger.Debug("Short circuiting HTTP rules due to rule allowing all and no other rules needing attention",
						logfields.EndpointID, ep.GetID(),
						logfields.TrafficDirection, dir,
						logfields.Port, port,
					)
					rules = nil
				}
			}

			// NPDS supports port ranges.
			PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
				Port:     uint32(port),
				EndPort:  uint32(l4.EndPort),
				Protocol: protocol,
				Rules:    envoypolicy.SortPortNetworkPolicyRules(rules),
			})
		}
	}
	if len(PerPortPolicies) == 0 || len(PerPortPolicies) == 0 && wildcardAllowAll {
		return nil
	}

	return envoypolicy.SortPortNetworkPolicies(PerPortPolicies)
}

// getNetworkPolicy converts a network policy into a cilium.NetworkPolicy.
func (s *xdsServer) getNetworkPolicy(ep endpoint.EndpointUpdater, selectors policy.SelectorSnapshot, names []string, l4Policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext, useSDS bool, policySecretsNamespace string,
) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		EndpointIps:      names,
		EndpointId:       ep.GetID(),
		ConntrackMapName: "global",
	}

	var ingressMap policy.L4PolicyMaps
	var egressMap policy.L4PolicyMaps
	if l4Policy != nil {
		ingressMap = l4Policy.Ingress.PortRules
		egressMap = l4Policy.Egress.PortRules
	}
	p.IngressPerPortPolicies = s.getDirectionNetworkPolicy(ep, selectors, ingressMap, ingressPolicyEnforced, useFullTLSContext, useSDS, "ingress", policySecretsNamespace)
	p.EgressPerPortPolicies = s.getDirectionNetworkPolicy(ep, selectors, egressMap, egressPolicyEnforced, useFullTLSContext, useSDS, "egress", policySecretsNamespace)

	return p
}

// return the Envoy proxy node IDs that need to ACK the policy.
func getNodeIDs(ep endpoint.EndpointUpdater, policy *policy.L4Policy) []string {
	nodeIDs := make([]string, 0, 1)

	// Host proxy uses "127.0.0.1" as the nodeID
	nodeIDs = append(nodeIDs, "127.0.0.1")
	return nodeIDs
}

func (s *xdsServer) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if s.proxyListeners == 0 {
		wg = nil
	}

	nodeIDs := getNodeIDs(ep, &policy.SelectorPolicy.L4Policy)

	// only wait for the most current policy to be acked when no (new) policy is given
	s.NetworkPolicyMutator.UseCurrent(NetworkPolicyTypeURL, nodeIDs, wg)
}

// ErrNotImplemented is the error returned by gRPC methods that are not
// implemented by Cilium.
var ErrNilPolicy = errors.New("nil EndpointPolicy")

func (s *xdsServer) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, epp *policy.EndpointPolicy, wg *completion.WaitGroup,
) (error, func() error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if epp == nil {
		return ErrNilPolicy, nil
	}

	l4policy := &epp.SelectorPolicy.L4Policy
	ingressPolicyEnforced := epp.SelectorPolicy.IngressPolicyEnabled
	egressPolicyEnforced := epp.SelectorPolicy.EgressPolicyEnabled
	selectors := epp.GetPolicySelectors()

	// Error out if the selectors are no longer valid
	if !selectors.IsValid() {
		return policy.ErrStaleSelectors, nil
	}

	ips := ep.GetPolicyNames()
	if len(ips) == 0 {
		// It looks like the "host EP" (identity == 1) has no IPs, so it is possible to find
		// there are no IPs here. In this case just skip without updating a policy, as
		// policies are always keyed by an IP.
		//
		// TODO: When L7 policy support for the host is needed, all host IPs should be
		// considered here?
		s.logger.Debug("Endpoint has no IP addresses or name",
			logfields.Name, ips,
			logfields.EndpointID, ep.GetID(),
		)
		return nil, func() error { return nil }
	}

	networkPolicy := s.getNetworkPolicy(ep, selectors, ips, l4policy, ingressPolicyEnforced, egressPolicyEnforced, s.config.useFullTLSContext, s.config.useSDS, s.secretManager.GetSecretSyncNamespace())

	// First, validate the policy
	err := networkPolicy.Validate()
	if err != nil {
		return fmt.Errorf("error validating generated NetworkPolicy for %d/%s: %w", ep.GetID(), ep.GetPolicyNames(), err), nil
	}

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if s.proxyListeners == 0 {
		wg = nil
	}

	// When successful, push policy into the cache.
	var callback func(error)
	policyRevision := l4policy.Revision
	callback = func(err error) {
		if err == nil {
			go ep.OnProxyPolicyUpdate(policyRevision)
		}
	}

	epID := ep.GetID()
	nodeIDs := getNodeIDs(ep, l4policy)
	resourceName := strconv.FormatUint(epID, 10)
	revertFunc := s.NetworkPolicyMutator.Upsert(NetworkPolicyTypeURL, resourceName, networkPolicy, nodeIDs, wg, callback)
	revertUpdatedNetworkPolicyEndpoints := make(map[string]endpoint.EndpointUpdater, len(ips))
	for _, ip := range ips {
		revertUpdatedNetworkPolicyEndpoints[ip] = s.localEndpointStore.getLocalEndpoint(ip)
		s.localEndpointStore.setLocalEndpoint(ip, ep)
	}

	return nil, func() error {
		s.logger.Debug("Reverting xDS network policy update")

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

		s.logger.Debug("Finished reverting xDS network policy update")

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
	PortAllocationCallbacks map[string]func(context.Context) error `json:"-" yaml:"-"`
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

		s.logger.Debug("UpsertEnvoyResources: Upserting Envoy resources",
			logfields.Resource, msg,
		)
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
		s.logger.Debug("Envoy upsertSecret",
			logfields.ResourceName, r.Name,
		)
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, nil))
	}
	for _, r := range resources.Endpoints {
		s.logger.Debug("Envoy upsertEndpoint",
			logfields.ResourceName, r.ClusterName,
			logfields.Resource, r,
		)
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, nil))
	}
	for _, r := range resources.Clusters {
		s.logger.Debug("Envoy upsertCluster",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg))
	}
	for _, r := range resources.Routes {
		s.logger.Debug("Envoy upsertRoute",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, nil))
	}
	// Wait before new Listeners are added if clusters were also added above.
	if wg != nil {
		start := time.Now()
		s.logger.Debug("UpsertEnvoyResources: Waiting for cluster updates to complete...")
		err := wg.Wait()
		s.logger.Debug("UpsertEnvoyResources: Wait time for cluster updates",
			logfields.Duration, time.Since(start),
			logfields.Error, err,
		)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			s.logger.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
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
		s.logger.Debug("Envoy upsertListener",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg,
			// this callback is not called if there is no change
			func(err error) {
				if err == nil && resources.PortAllocationCallbacks[listenerName] != nil {
					if callbackErr := resources.PortAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						s.logger.Warn("Failure in port allocation callback",
							logfields.Error, callbackErr,
						)
					}
				}
			}))
	}
	if wg != nil {
		start := time.Now()
		s.logger.Debug("UpsertEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		s.logger.Debug("UpsertEnvoyResources: Wait time for proxy updates",
			logfields.Duration, time.Since(start),
			logfields.Error, err,
		)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			s.logger.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
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
					s.logger.Debug("UpdateEnvoyResources: port changing",
						logfields.Listener, newListener.Name,
						logfields.ValueBefore, port,
						logfields.ValueAfter, addr.GetPortValue(),
					)
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
	s.logger.Debug("UpdateEnvoyResources: listeners",
		logfields.ResourcesDeleted, len(deleteListeners),
		logfields.ResourcesUpserted, len(new.Listeners),
	)
	for _, listener := range deleteListeners {
		listenerName := listener.Name
		revertFuncs = append(revertFuncs, s.deleteListener(listener.Name, wg,
			func(err error) {
				if err == nil && old.PortAllocationCallbacks[listenerName] != nil {
					if callbackErr := old.PortAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						s.logger.Warn("Failure in port allocation callback",
							logfields.Error, callbackErr)
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
	s.logger.Debug("UpdateEnvoyResources: routes",
		logfields.ResourcesDeleted, len(deleteRoutes),
		logfields.ResourcesUpserted, len(new.Routes),
	)
	for _, route := range deleteRoutes {
		revertFuncs = append(revertFuncs, s.deleteRoute(route.Name, nil))
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
	s.logger.Debug("UpdateEnvoyResources: clusters",
		logfields.ResourcesDeleted, len(deleteClusters),
		logfields.ResourcesUpserted, len(new.Clusters),
	)
	for _, cluster := range deleteClusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(cluster.Name, nil))
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
	s.logger.Debug("UpdateEnvoyResources: endpoints",
		logfields.ResourcesDeleted, len(deleteEndpoints),
		logfields.ResourcesUpserted, len(new.Endpoints),
	)
	for _, endpoint := range deleteEndpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(endpoint.ClusterName, nil))
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
	s.logger.Debug("UpdateEnvoyResources: secrets",
		logfields.ResourcesDeleted, len(deleteSecrets),
		logfields.ResourcesUpserted, len(new.Secrets),
	)
	for _, secret := range deleteSecrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(secret.Name, nil))
	}

	// Have to wait for deletes to complete before adding new listeners if a listener's port number is changed.
	if wg != nil && waitForDelete {
		start := time.Now()
		s.logger.Debug("UpdateEnvoyResources: Waiting for proxy deletes to complete...")
		err := wg.Wait()
		if err != nil {
			s.logger.Debug("UpdateEnvoyResources: delete failed",
				logfields.Error, err,
			)
		}
		s.logger.Debug("UpdateEnvoyResources: Finished waiting for proxy deletes",
			logfields.Duration, time.Since(start),
		)
		// new wait group for adds
		wg = completion.NewWaitGroup(ctx)
	}

	// Add new Secrets
	for _, r := range new.Secrets {
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, nil))
	}
	// Add new Endpoints
	for _, r := range new.Endpoints {
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, nil))
	}
	// Add new Clusters
	for _, r := range new.Clusters {
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg))
	}
	// Add new Routes
	for _, r := range new.Routes {
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, nil))
	}
	if wg != nil && len(new.Clusters) > 0 {
		start := time.Now()
		s.logger.Debug("UpdateEnvoyResources: Waiting for cluster updates to complete...")
		err := wg.Wait()
		if err != nil {
			s.logger.Debug("UpdateEnvoyResources: cluster update failed",
				logfields.Error, err,
			)
		}
		s.logger.Debug("UpdateEnvoyResources: Finished waiting for cluster updates",
			logfields.Duration, time.Since(start),
		)
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
						s.logger.Warn("Failure in port allocation callback",
							logfields.Error, callbackErr,
						)
					}
				}
			}))
	}

	if wg != nil {
		logArgs := []any{logfields.Duration, time.Since(time.Now())}
		s.logger.Debug("UpdateEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		if err != nil {
			logArgs = append(logArgs, logfields.Error, err)
		}
		s.logger.Debug("UpdateEnvoyResources: Finished waiting for proxy updates", logArgs...)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			s.logger.Debug("UpdateEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

func (s *xdsServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	s.logger.Debug("DeleteEnvoyResources: Deleting Envoy resources",
		logfields.ResourceListeners, len(resources.Listeners),
		logfields.ResourceRoutes, len(resources.Routes),
		logfields.ResourceClusters, len(resources.Clusters),
		logfields.ResourceEndpoints, len(resources.Endpoints),
		logfields.ResourceSecrets, len(resources.Secrets),
	)
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
						s.logger.Warn("Failure in port allocation callback",
							logfields.Error, callbackErr,
						)
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
		revertFuncs = append(revertFuncs, s.deleteRoute(r.Name, nil))
	}
	for _, r := range resources.Clusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(r.Name, nil))
	}
	for _, r := range resources.Endpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(r.ClusterName, nil))
	}
	for _, r := range resources.Secrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(r.Name, nil))
	}

	if wg != nil {
		logArgs := []any{logfields.Duration, time.Since(time.Now())}
		s.logger.Debug("DeleteEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		if err != nil {
			logArgs = append(logArgs, logfields.Error, err)
		}
		s.logger.Debug("DeleteEnvoyResources: Finished waiting for proxy updates", logArgs...)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			s.logger.Debug("DeleteEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}
