// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// TODO(nezdolik) start using new Resources interface in xds_server_impl.go
package envoy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	_ "github.com/cilium/cilium/pkg/envoy/resource"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
)

// XDSServer is an alias for xds.XDSServer, re-exported from the envoy package
// for backwards compatibility.
type XDSServer = xds.XDSServer

const (
	adminClusterName      = "/envoy-admin"
	egressClusterName     = "egress-cluster"
	egressTLSClusterName  = "egress-cluster-tls"
	ingressClusterName    = "ingress-cluster"
	ingressTLSClusterName = "ingress-cluster-tls"
	metricsListenerName   = "envoy-prometheus-metrics-listener"
	adminListenerName     = "envoy-admin-listener"
)

type xdsServer struct {
	logger *slog.Logger

	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// accessLogPath is the path to the L7 access logs
	accessLogPath string

	config xdsServerConfig

	// mutex protects accesses to the configuration Resources below.
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

	// npdsListeners tracks the set of listener names configured to start an NPDS client
	// for network policy enforcement.
	// When this set is empty, cilium should not wait for NACKs/ACKs from envoy for
	// network policy mutations.
	// mutex must be held during access.
	npdsListeners npdsListenersTracker

	// networkPolicyCache publishes network policy configuration updates to
	// Envoy proxies.
	networkPolicyCache *xds.Cache

	// networkPolicyMutator wraps networkPolicyCache to publish policy
	// updates to Envoy proxies.
	networkPolicyMutator xds.AckingResourceMutator

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

// npdsListenersTracker tracks the set of listener names that require NPDS.
type npdsListenersTracker map[string]struct{}

// Add inserts name into the tracker and returns a function that reverts the change.
func (t npdsListenersTracker) Add(name string) func() {
	if _, ok := t[name]; ok {
		return func() {}
	}

	t[name] = struct{}{}
	return func() { delete(t, name) }
}

// Delete removes name from the tracker and returns a function that reverts the removal.
// If name was not present the returned revert is a no-op.
func (t npdsListenersTracker) Delete(name string) func() {
	if _, ok := t[name]; !ok {
		return func() {}
	}

	delete(t, name)
	return func() {
		t[name] = struct{}{}
	}
}

// Empty returns true when no listeners are tracked.
func (t npdsListenersTracker) Empty() bool {
	return len(t) == 0
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
	envoyAccessLogEnabled         bool
}

// newXDSServer creates a new xDS GRPC server.
func newXDSServer(logger *slog.Logger, restorerPromise promise.Promise[endpointstate.Restorer], ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager) *xdsServer {
	xdsServer := &xdsServer{
		logger:             logger,
		restorerPromise:    restorerPromise,
		listenerCount:      make(map[string]uint),
		npdsListeners:      make(npdsListenersTracker),
		ipCache:            ipCache,
		localEndpointStore: localEndpointStore,

		socketPath:    util.GetXDSSocketPath(config.envoySocketDir),
		config:        config,
		secretManager: secretManager,
	}
	if config.envoyAccessLogEnabled {
		xdsServer.accessLogPath = util.GetAccessLogSocketPath()
	}

	xdsServer.initializeXdsConfigs()

	return xdsServer
}

func (s *xdsServer) run(ctx context.Context) error {
	return s.runXDSGRPCServer(ctx, s.resourceConfig)
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
	s.networkPolicyMutator = npdsMutator

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
	os.MkdirAll(util.GetSocketDir(socketsDir), 0o777)

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

func (s *xdsServer) AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
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
					TypedConfig: ToAny(&envoy_extensions_filters_http_router_v3.Router{}),
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
						TypedConfig: ToAny(hcmConfig),
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

func (s *xdsServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
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
					TypedConfig: ToAny(&envoy_extensions_filters_http_router_v3.Router{}),
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
			Address: GetPublicListenerAddress(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled()),
			FilterChains: []*envoy_config_listener.FilterChain{{
				Filters: []*envoy_config_listener.Filter{{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: ToAny(hcmConfig),
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
			_ = s.npdsListeners.Add(name)
		}
		s.logger.Info("Envoy: Upserting new listener",
			logfields.Listener, name,
		)
	}
	count++
	s.listenerCount[name] = count
	_ = s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConfig, []string{"127.0.0.1"}, wg,
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

	var revertNPDSTracking func()

	requireNPDS := listenerRequiresNPDS(listenerConf)
	if requireNPDS {
		revertNPDSTracking = s.npdsListeners.Add(name)
	} else {
		revertNPDSTracking = s.npdsListeners.Delete(name)
		if s.npdsListeners.Empty() {
			s.networkPolicyMutator.CancelCompletions(NetworkPolicyTypeURL)
		}
	}

	// 'callback' is not called if there is no change and this configuration has already been acked.
	revertFunc := s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg, callback)
	return func() {
		s.mutex.Lock()
		revertFunc()
		revertNPDSTracking()
		s.mutex.Unlock()
	}
}

// deleteListener deletes an LDS Envoy Listener.
func (s *xdsServer) deleteListener(name string, wg *completion.WaitGroup, callback func(error)) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	revertNPDSTracking := s.npdsListeners.Delete(name)
	if s.npdsListeners.Empty() {
		s.networkPolicyMutator.CancelCompletions(NetworkPolicyTypeURL)
	}

	// 'callback' is not called if there is no change and this configuration has already been acked.
	revertFunc := s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg, callback)
	return func() {
		s.mutex.Lock()
		revertNPDSTracking()
		revertFunc()
		s.mutex.Unlock()
	}
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
					TypedConfig: ToAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
			GetListenerFilter(isIngress, mayUseOriginalSourceAddr, port, lingerConfig),
		},
	}

	// Add filter chains
	if kind == policy.ParserTypeHTTP {
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetHttpFilterChainProto(clusterName, false, isIngress, s.accessLogPath, s.config))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetHttpFilterChainProto(tlsClusterName, true, isIngress, s.accessLogPath, s.config))
	} else {
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetTcpFilterChainProto(clusterName, false, s.accessLogPath))
		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetTcpFilterChainProto(tlsClusterName, true, s.accessLogPath))
	}
	return listenerConf
}

func (s *xdsServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	s.logger.Debug("Envoy: AddListener",
		logfields.L7ParserType, kind,
		logfields.Listener, name,
		logfields.MayUseOriginalSourceAddr, mayUseOriginalSourceAddr,
	)

	return s.addListener(name, func() *envoy_config_listener.Listener {
		return s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr)
	}, wg, cb, true)
}

func (s *xdsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	return s.removeListener(name, wg, true)
}

// removeListener removes an existing Envoy Listener.
func (s *xdsServer) removeListener(name string, wg *completion.WaitGroup, isProxyListener bool) xds.AckingResourceMutatorRevertFunc {
	s.logger.Debug("Envoy: RemoveListener",
		logfields.Listener, name,
	)

	var listenerRevertFunc xds.AckingResourceMutatorRevertFunc
	var revertNPDSTracking func()

	s.mutex.Lock()
	count := s.listenerCount[name]
	if count > 0 {
		count--
		if count == 0 {
			if isProxyListener {
				revertNPDSTracking = s.npdsListeners.Delete(name)
			}
			delete(s.listenerCount, name)
			s.logger.Info("Envoy: Deleting listener",
				logfields.Listener, name,
			)
			listenerRevertFunc = s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg, nil)

			// cancel all pending network policy completions if this was the last
			// listener with bpf metadata listener filter with bpf path configured.
			if s.npdsListeners.Empty() {
				s.networkPolicyMutator.CancelCompletions(NetworkPolicyTypeURL)
			}
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

	return func() {
		s.mutex.Lock()
		if listenerRevertFunc != nil {
			listenerRevertFunc()
		}
		if revertNPDSTracking != nil {
			revertNPDSTracking()
		}
		s.listenerCount[name] = s.listenerCount[name] + 1
		s.mutex.Unlock()
	}
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

// ErrNotImplemented is the error returned by gRPC methods that are not
// implemented by Cilium.
var ErrNilPolicy = errors.New("nil EndpointPolicy")

// UpdateNetworkPolicy returns nil revert/finalize funcs with synchronous errors.
func (s *xdsServer) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, epp *policy.EndpointPolicy, wg *completion.WaitGroup,
) (error, revert.RevertFunc, revert.FinalizeFunc) {
	if epp == nil {
		return ErrNilPolicy, nil, nil
	}

	names := ep.GetPolicyNames()
	if len(names) == 0 {
		// It looks like the "host EP" (identity == 1) has no IPs, so it is possible to find
		// there are no policy names here. In this case just skip without updating a policy.
		s.logger.Debug("Endpoint has no policy names",
			logfields.Name, names,
			logfields.EndpointID, ep.GetID(),
		)
		return nil, func() error { return nil }, func() {}
	}

	l4policy := &epp.SelectorPolicy.L4Policy
	ingressPolicyEnforced := epp.SelectorPolicy.IngressPolicyEnabled
	egressPolicyEnforced := epp.SelectorPolicy.EgressPolicyEnabled
	selectors := epp.GetPolicySelectors()

	// Error out if the selectors are no longer valid
	if !selectors.IsValid() {
		return policy.ErrStaleSelectors, nil, nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Update local endpoint IP/policy mapping for access log correlation and log any conflicts.
	// This is done even if policy update fails, as this information only depends on the
	// existence of the endpoint and does not need to be reverted even if policy update fails.
	conflicts := s.localEndpointStore.setLocalEndpoint(ep)
	if len(conflicts) > 0 {
		s.logger.Error("Conflicting policy names detected while updating local endpoint store",
			logfields.EndpointID, ep.GetID(),
			logfields.Info, conflicts,
		)

		// remove conflicting policies
		for _, dup := range conflicts {
			// We use the string form of the Endpoint's ID as the xDS resource name.
			dupName := strconv.FormatUint(dup.ep.GetID(), 10)
			s.networkPolicyMutator.Delete(NetworkPolicyTypeURL, dupName, nil, nil, nil)
		}
	}

	networkPolicy := GetNetworkPolicy(ep, epp.SelectorPolicy.GetEgressNamedPorts, selectors, names, l4policy, ingressPolicyEnforced, egressPolicyEnforced, s.config.useFullTLSContext, s.config.useSDS, s.secretManager.GetSecretSyncNamespace(), s.logger, s.l7RulesTranslator)

	// First, validate the policy
	err := networkPolicy.Validate()
	if err != nil {
		return fmt.Errorf("error validating generated NetworkPolicy for %d/%s: %w", ep.GetID(), ep.GetPolicyNames(), err), nil, nil
	}

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if s.npdsListeners.Empty() {
		wg = nil
	}

	// When successful, push policy into the cache.
	policyRevision := l4policy.Revision
	callback := func(err error) {
		if err == nil {
			go ep.OnProxyPolicyUpdate(policyRevision)
		}
	}
	epID := ep.GetID()
	nodeIDs := GetLegacyFormatNodeIDs(ep, l4policy)
	resourceName := strconv.FormatUint(epID, 10)
	revertFunc := s.networkPolicyMutator.Upsert(NetworkPolicyTypeURL, resourceName, networkPolicy, nodeIDs, wg, callback)

	return nil, func() error {
			s.logger.Debug("Reverting xDS network policy update",
				logfields.EndpointID, epID,
			)

			s.mutex.Lock()
			defer s.mutex.Unlock()

			revertFunc()

			s.logger.Debug("Finished reverting xDS network policy update")

			return nil
		}, func() {
			s.logger.Debug("Finalizing xDS network policy update",
				logfields.EndpointID, epID,
			)
		}
}

func (s *xdsServer) RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	epID := ep.GetID()
	resourceName := strconv.FormatUint(epID, 10)

	// Safe to pass nodeIPs as nil when wg is also nil and the returned revert function is
	// ignored.
	s.networkPolicyMutator.Delete(NetworkPolicyTypeURL, resourceName, nil, nil, nil)

	s.localEndpointStore.removeLocalEndpoint(ep)
}

func (s *xdsServer) RemoveAllNetworkPolicies(ctx context.Context) {
	s.networkPolicyCache.Clear(NetworkPolicyTypeURL)
}

func (s *xdsServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources) error {
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

		s.logger.Debug("UpsertEnvoyResources: Upserting Envoy Resources",
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
			revertFuncs.Revert()
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
			revertFuncs.Revert()
			s.logger.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

// UpdateEnvoyResources uses 'ctx' in Wait for Envoy N/ACK if resources contains listeners. This is
// needed due to the possible dependency between listeners and listeners and clusters. If resources
// includes listeners the caller MUST pass a context with a timeout to prevent indefinite blocking
// in case Envoy never responds.
func (s *xdsServer) UpdateEnvoyResources(ctx context.Context, old, new xds.Resources) error {
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

	// Have to wait for deletes to complete before adding new listeners if a listener's port
	// number is changed.
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
			revertFuncs.Revert()
			s.logger.Debug("UpdateEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

// DeleteEnvoyResources uses 'ctx' in Wait for Envoy N/ACK if resources contains listeners. If
// resources includes listeners the caller MUST pass a context with a timeout to prevent indefinite
// blocking in case Envoy never responds.
func (s *xdsServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources) error {
	s.logger.Debug("DeleteEnvoyResources: Deleting Envoy resources",
		logfields.ResourceListeners, len(resources.Listeners),
		logfields.ResourceRoutes, len(resources.Routes),
		logfields.ResourceClusters, len(resources.Clusters),
		logfields.ResourceEndpoints, len(resources.Endpoints),
		logfields.ResourceSecrets, len(resources.Secrets),
	)
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Wait only if new Listeners are removed, as they will always be acked.
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
			revertFuncs.Revert()
			s.logger.Debug("DeleteEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}
