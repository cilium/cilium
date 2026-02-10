// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// TODO(nezdolik) finish move updating of resources structure (syncing with snapshot) into cache itself
package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_mysql_proxy "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/network/mysql_proxy/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_mongo_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/mongo_proxy/v3"
	envoy_config_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	_ "github.com/cilium/cilium/pkg/envoy/resource"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/time"
)

const (
	localNodeID = "127.0.0.1"
)

type adsServer struct {
	logger *slog.Logger

	cache xdsnew.Cache

	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// accessLogPath is the path to the L7 access logs
	accessLogPath string

	config adsServerConfig

	// mutex protects accesses to the configuration resources below.
	mutex lock.RWMutex

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

	localEndpointStore *LocalEndpointStore

	l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator
	secretManager     certificatemanager.SecretManager
}

type adsServerConfig struct {
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

// newADSServer creates a new ADS GRPC server.
func newADSServer(logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config adsServerConfig, secretManager certificatemanager.SecretManager) *adsServer {
	adsServer := &adsServer{
		logger:             logger,
		cache:              xdsnew.NewCache(logger),
		ipCache:            ipCache,
		localEndpointStore: localEndpointStore,

		socketPath:    util.GetXDSSocketPath(config.envoySocketDir),
		accessLogPath: util.GetAccessLogSocketPath(config.envoySocketDir),
		config:        config,
		secretManager: secretManager,
	}

	adsServer.initializeXdsConfigs()

	return adsServer
}

func (s *adsServer) start(ctx context.Context) error {
	return s.startAdsGRPCServer(ctx, &s.cache)
}

func (s *adsServer) initializeXdsConfigs() {
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

	s.networkPolicyCache = npdsCache
	s.NetworkPolicyMutator = npdsMutator

	s.resourceConfig = map[string]*xds.ResourceTypeConfiguration{
		NetworkPolicyTypeURL:      npdsConfig,
		NetworkPolicyHostsTypeURL: nphdsConfig,
	}
}

func (s *adsServer) newSocketListener() (*net.UnixListener, error) {
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

func (s *adsServer) stop() {
	if s.stopFunc != nil {
		s.stopFunc()
	}
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath)
	}
}

func (s *adsServer) AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	s.logger.Debug("Envoy: AddAdminListener",
		logfields.Port, port,
	)

	s.addListener(ctx, adminListenerName, func() *envoy_config_listener.Listener {
		hcmConfig := &envoy_config_http.HttpConnectionManager{
			StatPrefix:       adminListenerName,
			UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
			SkipXffAppend:    true,
			HttpFilters: []*envoy_config_http.HttpFilter{{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: xdsnew.ToAny(&envoy_extensions_filters_http_router_v3.Router{}),
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
						TypedConfig: xdsnew.ToAny(hcmConfig),
					},
				}},
			}},
		}

		return listenerConf
	}, func(err error) {
		if err != nil {
			s.logger.Debug("Envoy: Adding admin listener failed",
				logfields.Port, port,
				logfields.Error, err,
			)
			// TODO(nezdolik) Is this needed?
			// Remove the added listener in case of a failure
			// s.removeListener(adminListenerNameNew, nil, false)
		} else {
			s.logger.Info("Envoy: Listening for Admin API",
				logfields.Port, port,
			)
		}
	})
}

func (s *adsServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	s.logger.Debug("Envoy: AddMetricsListener",
		logfields.Port, port,
	)

	s.addListener(ctx, metricsListenerName, func() *envoy_config_listener.Listener {
		hcmConfig := &envoy_config_http.HttpConnectionManager{
			StatPrefix:       metricsListenerName,
			UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
			SkipXffAppend:    true,
			HttpFilters: []*envoy_config_http.HttpFilter{{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: xdsnew.ToAny(&envoy_extensions_filters_http_router_v3.Router{}),
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
						TypedConfig: xdsnew.ToAny(hcmConfig),
					},
				}},
			}},
		}

		return listenerConf
	}, func(err error) {
		if err != nil {
			s.logger.Debug("Envoy: Adding metrics listener failed",
				logfields.Port, port,
				logfields.Error, err,
			)
			// TODO(nezdolik) Is this needed?
			// Remove the added listener in case of a failure
			// s.removeListener(adminListenerNameNew, nil, false)
		} else {
			s.logger.Info("Envoy: Listening for prometheus metrics",
				logfields.Port, port,
			)
		}
	})
}

// addListener either reuses an existing listener with 'name', or creates a new one.
// 'listenerConf()' is only called if a new listener is being created.
func (s *adsServer) addListener(ctx context.Context, name string, listenerConf func() *envoy_config_listener.Listener, cb func(err error)) error {
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

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Host proxy uses "127.0.0.1" as the nodeID
	oldSnapshot, err := s.cache.GetSnapshot(localNodeID)
	if err != nil {
		// TODO(nezdolik) this may be first update for this node, so snapshot may not exist yet
		s.logger.Error("Error getting snapshot for node %s: %q", localNodeID, err)
		return err
	}
	resources := s.cache.GetAllResources(localNodeID)
	resources.Listeners[listenerConfig.Name] = listenerConfig

	updatedSnapshot, err := s.cache.GenerateSnapshot(resources, s.logger)
	if s.cache.AreDifferentSnapshots(oldSnapshot, updatedSnapshot) {
		err = s.cache.SetSnapshot(ctx, localNodeID, updatedSnapshot)
		if err != nil {
			s.logger.Error("Error setting snapshot for node %s: %q", localNodeID, err)
			cb(err)
			return err
		} else {
			s.cache.SetResources(localNodeID, resources)
			return nil
		}
	} else {
		s.logger.Debug("addListener: Snapshots are identical, skipping update")
		return nil
	}
}

func (s *adsServer) getListenerConf(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool) *envoy_config_listener.Listener {
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
					TypedConfig: xdsnew.ToAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
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
		// Default TCP chain, takes care of all parsers in proxylib
		// The proxylib is deprecated and will be removed in the future
		// https://github.com/cilium/cilium/issues/38224
		s.logger.Warn("The support for Envoy Go Extensions (proxylib) has been deprecated due to lack of maintainers. If you are interested in helping to maintain, please reach out on GitHub or the official Cilium slack",
			logfields.URL, "https://slack.cilium.io")
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName, "", nil, false, s.accessLogPath, s.socketPath))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(tlsClusterName, "", nil, true, s.accessLogPath, s.socketPath))

		// Experimental TCP chain for MySQL 5.x
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName,
			"envoy.filters.network.mysql_proxy", xdsnew.ToAny(&envoy_mysql_proxy.MySQLProxy{
				StatPrefix: "mysql",
			}), false, s.accessLogPath, s.socketPath))

		// Experimental TCP chain for MongoDB
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName,
			"envoy.filters.network.mongo_proxy", xdsnew.ToAny(&envoy_mongo_proxy.MongoProxy{
				StatPrefix:          "mongo",
				EmitDynamicMetadata: true,
			}), false, s.accessLogPath, s.socketPath))
	}
	return listenerConf
}

func (s *adsServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	s.logger.Debug("Envoy: AddListener",
		logfields.L7ParserType, kind,
		logfields.Listener, name,
		logfields.MayUseOriginalSourceAddr, mayUseOriginalSourceAddr,
	)

	return s.addListener(ctx, name, func() *envoy_config_listener.Listener {
		return s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr)
	}, cb)
}

func (s *adsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	return s.removeListener(ctx, name)
}

// removeListener removes an existing Envoy Listener.
func (s *adsServer) removeListener(ctx context.Context, name string) xds.AckingResourceMutatorRevertFunc {
	s.logger.Debug("Envoy: RemoveListener",
		logfields.Listener, name,
	)
	revertFunc := func(*completion.Completion) {
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Host proxy uses "127.0.0.1" as the nodeID
	resources := s.cache.GetAllResources(localNodeID)
	delete(resources.Listeners, name)

	updatedSnapshot, err := s.cache.GenerateSnapshot(resources, s.logger)
	if err != nil {
		s.logger.Error("Error generating snapshot for node %s: %q", localNodeID, err)
		return revertFunc
	}

	err = s.cache.SetSnapshot(ctx, localNodeID, updatedSnapshot)
	if err == nil {
		s.cache.SetResources(localNodeID, resources)
	} else {
		s.logger.Error("Error setting snapshot for node %s: %q", localNodeID, err)
		return revertFunc
	}

	// TODO(nezdolik) clean up this return type after full ADS switch
	return revertFunc
}

func (s *adsServer) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if s.proxyListeners == 0 {
		wg = nil
	}

	nodeIDs := xdsnew.GetNodeIDs(ep, &policy.SelectorPolicy.L4Policy)

	// only wait for the most current policy to be acked when no (new) policy is given
	s.NetworkPolicyMutator.UseCurrent(NetworkPolicyTypeURL, nodeIDs, wg)
}

func (s *adsServer) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, epp *policy.EndpointPolicy,
	wg *completion.WaitGroup,
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

	epID := ep.GetID()
	nodeIDs := xdsnew.GetNodeIDs(ep, l4policy)
	resourceName := strconv.FormatUint(epID, 10)

	for _, nodeId := range nodeIDs {
		resources := s.cache.GetAllResources(nodeId)
		resources.NetworkPolicies[resourceName] = networkPolicy
		s.updateSnapshot(ctx, resources, nodeId)
	}

	return nil, func() error {
		return nil
	}
}

// TBD
func (s *adsServer) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
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

func (s *adsServer) RemoveAllNetworkPolicies() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// Host proxy uses "127.0.0.1" as the nodeID
	s.cache.ClearSnapshotForType(localNodeID, NetworkPolicyTypeURL)
}

func (s *adsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// Host proxy uses "127.0.0.1" as the nodeID
	resources := s.cache.GetAllResources(localNodeID)
	return resources.NetworkPolicies, nil
}

func (s *adsServer) updateSnapshot(ctx context.Context, resources *xds.Resources, nodeId string) error {
	if nodeId != "" {
		// Host proxy uses "127.0.0.1" as the nodeID
		nodeId = localNodeID
	}
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

		s.logger.Debug("updateXdsSnapshot: Updating Envoy resources",
			logfields.Resource, msg,
		)
	}
	for _, r := range resources.Secrets {
		s.logger.Debug("Envoy updateSecret",
			logfields.ResourceName, r.Name,
		)
	}
	for _, r := range resources.Endpoints {
		s.logger.Debug("Envoy updateEndpoint",
			logfields.ResourceName, r.ClusterName,
			logfields.Resource, r,
		)
	}
	for _, r := range resources.Clusters {
		s.logger.Debug("Envoy updateCluster",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
	}
	for _, r := range resources.Routes {
		s.logger.Debug("Envoy updateRoute",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	oldSnapshot, err := s.cache.GetSnapshot(nodeId)
	if err != nil {
		// TODO(nezdolik) this may be first update for this node, so snapshot may not exist yet
		s.logger.Error("Error getting snapshot for node %s: %q", nodeId, err)
		return err
	}
	newSnapshot, err := s.cache.GenerateSnapshot(resources, s.logger)
	if err != nil {
		return err
	}
	if s.cache.AreDifferentSnapshots(oldSnapshot, newSnapshot) {
		err = s.cache.SetSnapshot(ctx, nodeId, newSnapshot)
		if err != nil {
			s.logger.Error("Error setting snapshot for node %s: %q", nodeId, err)
			return err
		} else {
			s.cache.SetResources(nodeId, resources)
		}
	} else {
		s.logger.Debug("updateXdsSnapshot: Snapshots are identical, skipping update")
	}

	return nil
}

func (s *adsServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources) error {
	return s.updateSnapshot(ctx, &resources, "")
}

func (s *adsServer) UpdateEnvoyResources(ctx context.Context, oldResources, newResources xds.Resources) error {
	return s.updateSnapshot(ctx, &newResources, "")
}

func (s *adsServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.logger.Debug("DeleteEnvoyResources: Deleting Envoy resources",
		logfields.ResourceListeners, len(resources.Listeners),
		logfields.ResourceRoutes, len(resources.Routes),
		logfields.ResourceClusters, len(resources.Clusters),
		logfields.ResourceEndpoints, len(resources.Endpoints),
		logfields.ResourceSecrets, len(resources.Secrets),
	)

	currentResources := s.cache.GetAllResources(localNodeID)
	newResources := subtractResources(currentResources, &resources)

	return s.updateSnapshot(ctx, &newResources, "")
}

// Subtracts all resources present in b from a.
func subtractResources(a *xds.Resources, b *xds.Resources) xds.Resources {
	diffResources := xds.Resources{}

	for endpointName := range a.Endpoints {
		if endpoint, present := b.Endpoints[endpointName]; !present {
			diffResources.Endpoints[endpointName] = endpoint
		}
	}

	for clusterName := range a.Clusters {
		if cluster, present := b.Clusters[clusterName]; !present {
			diffResources.Clusters[clusterName] = cluster
		}
	}

	for routeName := range a.Routes {
		if route, present := b.Routes[routeName]; !present {
			diffResources.Routes[routeName] = route
		}
	}

	for listenerName := range a.Listeners {
		if listener, present := b.Listeners[listenerName]; !present {
			diffResources.Listeners[listenerName] = listener
		}
	}

	for secretName := range a.Secrets {
		if secret, present := b.Secrets[secretName]; !present {
			diffResources.Secrets[secretName] = secret
		}
	}

	for nwPolicyName := range a.NetworkPolicies {
		if nwPolicy, present := b.NetworkPolicies[nwPolicyName]; !present {
			diffResources.NetworkPolicies[nwPolicyName] = nwPolicy
		}
	}

	return diffResources
}

// getTcpFilterChainProto creates a TCP filter chain with the Cilium network filter.
// By default, the returned chain can be used with the Cilium Go extensions L7 parsers
// in 'proxylib' directory in the Cilium repo.
// When optional 'filterName' is given, it is configured as the first filter in the chain
// and 'proxylib' is not configured. In this case the returned filter chain is only used
// if the applicable network policy specifies 'filterName' as the L7 parser.
func (s *adsServer) getTcpFilterChainProto(clusterName string, filterName string, config *anypb.Any, tls bool, accessLogPath string, socketPath string) *envoy_config_listener.FilterChain {
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
				"access-log-path": accessLogPath,
				"xds-path":        socketPath,
			},
		}
	} else {
		// Envoy metadata logging requires accesslog path
		ciliumConfig = &cilium.NetworkFilter{
			AccessLogPath: accessLogPath,
		}
	}
	filters = append(filters, &envoy_config_listener.Filter{
		Name: "cilium.network",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: xdsnew.ToAny(ciliumConfig),
		},
	})

	// 3. Add the TCP proxy filter.
	filters = append(filters, &envoy_config_listener.Filter{
		Name: "envoy.filters.network.tcp_proxy",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: xdsnew.ToAny(&envoy_config_tcp.TcpProxy{
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
				TypedConfig: xdsnew.ToAny(&cilium.DownstreamTlsWrapperContext{}),
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

func (s *adsServer) getHttpFilterChainProto(clusterName string, tls bool, isIngress bool) *envoy_config_listener.FilterChain {
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
					TypedConfig: xdsnew.ToAny(&envoy_extensions_filters_http_router_v3.Router{}),
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
				TypedConfig: xdsnew.ToAny(&cilium.NetworkFilter{}),
			},
		}, {
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: xdsnew.ToAny(hcmConfig),
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
				TypedConfig: xdsnew.ToAny(&cilium.DownstreamTlsWrapperContext{}),
			},
		}
	}

	return chain
}

func (s *adsServer) getNetworkPolicy(ep endpoint.EndpointUpdater, selectors policy.SelectorSnapshot, names []string, l4Policy *policy.L4Policy,
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
	p.IngressPerPortPolicies = xdsnew.GetDirectionNetworkPolicy(ep, selectors, ingressMap, ingressPolicyEnforced, useFullTLSContext, useSDS, "ingress", policySecretsNamespace, s.logger, s.l7RulesTranslator)
	p.EgressPerPortPolicies = xdsnew.GetDirectionNetworkPolicy(ep, selectors, egressMap, egressPolicyEnforced, useFullTLSContext, useSDS, "egress", policySecretsNamespace, s.logger, s.l7RulesTranslator)

	return p
}
