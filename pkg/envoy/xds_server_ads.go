// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	_ "github.com/cilium/cilium/pkg/envoy/resource"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
)

const (
	localNodeID = LocalNodeID
)

type adsServer struct {
	logger *slog.Logger

	cache xdsnew.Cache

	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// accessLogPath is the path to the L7 access logs
	accessLogPath string

	config xdsServerConfig

	// mutex protects accesses to the configuration resources below.
	mutex lock.RWMutex

	// proxyListeners is the count of redirection proxy listeners in 'listeners'.
	// This value is different from len(listeners) due to non-proxy listeners
	// (e.g., prometheus listener)
	proxyListeners int

	// npdsListeners tracks the set of listener names configured to start an
	// NPDS client for network policy enforcement.
	// When this set is empty, cilium should not wait for NACKs/ACKs from envoy
	// for network policy mutations.
	// mutex must be held during access.
	npdsListeners npdsListenersTracker

	// listenerCount is the set of names of listeners that have been added by
	// calling addListener.
	// mutex must be held when accessing this.
	// Value holds the number of redirects using the listener named by the key.
	listenerCount map[string]uint

	// resourceGeneration is the latest generation allocated from the global ADS
	// resource-state sequence. Generations are unique across all nodes.
	// mutex must be held during access.
	resourceGeneration uint64

	// resourceGenerations identifies the latest resource state staged for each
	// node. Revert closures use the node's generation as a cheap stale-update
	// guard without treating updates to other nodes as superseding it.
	// mutex must be held during access.
	resourceGenerations map[string]uint64

	// stopFunc contains the function which stops the xDS gRPC server.
	stopFunc context.CancelFunc

	// IPCache is used for tracking IP->Identity mappings and propagating
	// them to the proxy via NPHDS in the cases described
	ipCache IPCacheEventSource

	localEndpointStore *LocalEndpointStore

	l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator
	secretManager     certificatemanager.SecretManager

	restorerPromise promise.Promise[endpointstate.Restorer]
}

func newADSServerWithCache(cache xdsnew.Cache, logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	adsServer := &adsServer{
		logger:              logger,
		cache:               cache,
		ipCache:             ipCache,
		localEndpointStore:  localEndpointStore,
		config:              config,
		secretManager:       secretManager,
		socketPath:          util.GetXDSSocketPath(config.envoySocketDir),
		accessLogPath:       util.GetAccessLogSocketPath(config.envoySocketDir),
		restorerPromise:     restorerPromise,
		listenerCount:       make(map[string]uint),
		npdsListeners:       make(npdsListenersTracker),
		resourceGenerations: make(map[string]uint64),
	}
	return adsServer
}

// newADSServer creates a new ADS GRPC server.
func newADSServer(logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	return newADSServerWithCache(xdsnew.NewCache(logger, config.envoyXDSMode.IsStrictADS()), logger, ipCache, localEndpointStore, config, secretManager, restorerPromise)
}

func (s *adsServer) run(ctx context.Context) error {
	return s.startAdsGRPCServer(ctx)
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
		s.logger.Warn(
			"Envoy: Failed to change the group of xDS listen socket",
			logfields.Path, s.socketPath,
			logfields.Error, err,
		)
	}
	return socketListener, nil
}

func (s *adsServer) AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	s.logger.Debug(
		"Envoy: AddAdminListener",
		logfields.Port, port,
	)

	s.addListener(ctx, adminListenerName, func() *envoy_config_listener.Listener {
		return s.getAdminListenerConfig(port)
	}, wg, func(err error) {
		if err != nil {
			s.logger.Debug(
				"Envoy: Adding admin listener failed",
				logfields.Port, port,
				logfields.Error, err,
			)
			// Remove the added listener in case of a failure
			s.removeListener(ctx, adminListenerName, nil, false)
		} else {
			s.logger.Info(
				"Envoy: Listening for Admin API",
				logfields.Port, port,
			)
		}
	}, false)
}

func (s *adsServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	s.logger.Debug(
		"Envoy: AddMetricsListener",
		logfields.Port, port,
	)
	s.addListener(ctx, metricsListenerName, func() *envoy_config_listener.Listener {
		return s.getMetricsListenerConfig(port)
	}, wg, func(err error) {
		if err != nil {
			s.logger.Debug(
				"Envoy: Adding metrics listener failed",
				logfields.Port, port,
				logfields.Error, err,
			)
			// Remove the added listener in case of a failure
			s.removeListener(ctx, metricsListenerName, nil, false)
		} else {
			s.logger.Info(
				"Envoy: Listening for prometheus metrics",
				logfields.Port, port,
			)
		}
	}, false)
}

func (s *adsServer) getMetricsListenerConfig(port uint16) *envoy_config_listener.Listener {
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
}

// addListener either reuses an existing listener with 'name', or creates a new one.
// 'listenerConf()' is only called if a new listener is being created.
// If isProxyListener is true, the listener is counted in proxyListeners.
func (s *adsServer) addListener(ctx context.Context, name string, listenerConf func() *envoy_config_listener.Listener, wg *completion.WaitGroup, cb func(err error), isProxyListener bool) error {
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

	count := s.listenerCount[name]
	if count == 0 {
		if isProxyListener {
			s.proxyListeners++
		}
		s.logger.Info(
			"Envoy: Upserting new listener",
			logfields.Listener, name,
		)
	}
	count++
	s.listenerCount[name] = count

	var callbackTypeURLs map[string]func(error)
	if wg != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: cb}
	}
	mutations := xdsnew.ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{name: listenerConfig}}}
	if _, err := s.applyResourceUpdate(ctx, localNodeID, mutations, wg, callbackTypeURLs); err != nil {
		return err
	}
	if wg == nil && cb != nil {
		cb(nil)
	}
	return nil
}

func (s *adsServer) getAdminListenerConfig(port uint16) *envoy_config_listener.Listener {
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
					TypedConfig: ToAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
			GetListenerFilter(isIngress, mayUseOriginalSourceAddr, port, lingerConfig, &s.config),
		},
	}

	// Add filter chains
	if kind == policy.ParserTypeHTTP {
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetHttpFilterChainProto(clusterName, false, isIngress, s.accessLogPath, s.config))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetHttpFilterChainProto(tlsClusterName, true, isIngress, s.accessLogPath, s.config))
	} else {
		// Default TCP chain, takes care of all parsers in proxylib
		// The proxylib is deprecated and will be removed in the future
		// https://github.com/cilium/cilium/issues/38224
		s.logger.Warn("The support for Envoy Go Extensions (proxylib) has been deprecated due to lack of maintainers. If you are interested in helping to maintain, please reach out on GitHub or the official Cilium slack",
			logfields.URL, "https://slack.cilium.io")
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetTcpFilterChainProto(clusterName, false, s.accessLogPath))

		// Add a TLS variant
		listenerConf.FilterChains = append(listenerConf.FilterChains, GetTcpFilterChainProto(tlsClusterName, true, s.accessLogPath))
	}
	return listenerConf
}

func (s *adsServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	s.logger.Debug(
		"Envoy: AddListener",
		logfields.L7ParserType, kind,
		logfields.Listener, name,
		logfields.MayUseOriginalSourceAddr, mayUseOriginalSourceAddr,
	)

	return s.addListener(ctx, name, func() *envoy_config_listener.Listener {
		return s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr)
	}, wg, cb, true)
}

func (s *adsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	return s.removeListener(ctx, name, wg, true)
}

// removeListener removes an existing Envoy Listener.
// The listener is only actually deleted when the reference count reaches zero.
func (s *adsServer) removeListener(ctx context.Context, name string, wg *completion.WaitGroup, isProxyListener bool) xds.AckingResourceMutatorRevertFunc {
	s.logger.Debug(
		"Envoy: RemoveListener",
		logfields.Listener, name,
	)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	count := s.listenerCount[name]
	if count == 0 {
		// Bail out if this listener does not exist
		s.logger.Error(
			"Envoy: Attempt to remove non-existent listener",
			logfields.Listener, name,
		)
		return func() {}
	}

	count--
	if count > 0 {
		// Other redirects still using this listener, just decrement.
		s.listenerCount[name] = count
		return func() {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			s.listenerCount[name]++
		}
	}

	// count == 0: actually delete the listener.
	if isProxyListener {
		s.proxyListeners--
	}
	delete(s.listenerCount, name)

	// Cancel all pending network policy completions if this was the last
	// proxy listener, since Envoy will never ACK them.
	if isProxyListener && s.proxyListeners == 0 {
		s.cache.GetCompletionCallbacks().CancelPendingCompletions(NetworkPolicyTypeURL)
	}

	s.logger.Info(
		"Envoy: Deleting listener",
		logfields.Listener, name,
	)

	// Host proxy uses "127.0.0.1" as the nodeID
	resources := s.cache.GetAllResources(localNodeID)

	// Capture old listener for revert.
	var oldListener *envoy_config_listener.Listener
	if resources != nil {
		oldListener = resources.Listeners[name]
	}
	existed := oldListener != nil

	var callbackTypeURLs map[string]func(error)
	if wg != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: nil}
	}
	mutations := xdsnew.ResourceMutations{Removed: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{name: oldListener}}}
	_, _ = s.applyResourceUpdate(ctx, localNodeID, mutations, wg, callbackTypeURLs)

	return func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		if existed {
			s.logger.Debug("Reverting listener removal", logfields.Listener, name)
			mutations := xdsnew.ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{name: oldListener}}}
			_, _ = s.applyResourceUpdate(ctx, localNodeID, mutations, nil, nil)
		}
		if isProxyListener {
			s.proxyListeners++
		}
		s.listenerCount[name]++
	}
}

func (s *adsServer) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, epp *policy.EndpointPolicy,
	wg *completion.WaitGroup,
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

		// Remove network policies for conflicting endpoints from the cache.
		for _, dup := range conflicts {
			dupName := strconv.FormatUint(dup.ep.GetID(), 10)
			mutations := xdsnew.ResourceMutations{Removed: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{dupName: nil}}}
			_, _ = s.applyResourceUpdate(ctx, localNodeID, mutations, nil, nil)
		}
	}

	networkPolicy := s.getNetworkPolicy(ep, epp.SelectorPolicy.GetEgressNamedPorts, selectors, names, l4policy, ingressPolicyEnforced, egressPolicyEnforced, s.config.useFullTLSContext, s.config.useSDS, s.secretManager.GetSecretSyncNamespace())

	// First, validate the policy
	err := networkPolicy.Validate()
	if err != nil {
		return fmt.Errorf("error validating generated NetworkPolicy for %d/%s: %w", ep.GetID(), ep.GetPolicyNames(), err), nil, nil
	}

	epID := ep.GetID()
	nodeIDs := GetNodeIDs(ep, l4policy)
	resourceName := strconv.FormatUint(epID, 10)

	// If there are no listeners configured that start an NPDS client, the local
	// node's Envoy proxy won't query for network policies and therefore will
	// never ACK them, and we'd wait forever.
	waitForACK := wg != nil && !s.npdsListeners.Empty()
	if !waitForACK {
		wg = nil
	}

	// When successful, notify the endpoint that its proxy policy was accepted.
	policyRevision := l4policy.Revision
	callback := func(err error) {
		if err == nil {
			go ep.OnProxyPolicyUpdate(policyRevision)
		}
	}

	var resourceUpdates []resourceUpdate
	for _, nodeId := range nodeIDs {
		var callbackTypeURLs map[string]func(error)
		if waitForACK {
			callbackTypeURLs = map[string]func(error){NetworkPolicyTypeURL: callback}
		}
		mutations := xdsnew.ResourceMutations{Upserted: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{resourceName: networkPolicy}}}
		update, err := s.applyResourceUpdate(ctx, nodeId, mutations, wg, callbackTypeURLs)
		if err != nil {
			return err, nil, nil
		}
		if update.changed() {
			resourceUpdates = append(resourceUpdates, update)
		}
	}
	if !waitForACK {
		callback(nil)
	}

	return nil, func() error {
			s.logger.Debug("Reverting xDS network policy update")

			// Use the same generation-fenced inverse transaction that a NACK
			// would use. If a NACK already applied it, the revert is idempotent.
			for _, update := range resourceUpdates {
				update.revert()
			}

			s.logger.Debug("Finished reverting xDS network policy update")
			return nil
		}, func() {
			s.logger.Debug("Finalizing xDS network policy update",
				logfields.EndpointID, epID,
			)
		}
}

func (s *adsServer) RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	epID := ep.GetID()
	resourceName := strconv.FormatUint(epID, 10)

	s.logger.Debug(
		"Envoy: RemoveNetworkPolicy",
		logfields.CiliumNetworkPolicyName, resourceName,
	)

	ip := ep.GetIPv6Address()
	if ip != "" {
		s.localEndpointStore.removeLocalEndpoint(ep)
	}
	ip = ep.GetIPv4Address()
	if ip != "" {
		s.localEndpointStore.removeLocalEndpoint(ep)
	}

	mutations := xdsnew.ResourceMutations{Removed: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{resourceName: nil}}}
	_, _ = s.applyResourceUpdate(ctx, localNodeID, mutations, nil, nil)
}

func (s *adsServer) RemoveAllNetworkPolicies() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	resources := s.cache.GetAllResources(localNodeID)
	if resources == nil {
		return
	}
	mutations := xdsnew.ResourceMutations{Removed: xds.Resources{NetworkPolicies: resources.NetworkPolicies}}
	if _, err := s.applyResourceUpdate(context.Background(), localNodeID, mutations, nil, nil); err != nil {
		s.logger.Error("Failed to remove all network policies", logfields.Error, err)
	}
}

func (s *adsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// Host proxy uses "127.0.0.1" as the nodeID
	resources := s.cache.GetAllResources(localNodeID)

	policies := resources.NetworkPolicies
	if len(resourceNames) > 0 {
		policies = make(map[string]*cilium.NetworkPolicy, len(resourceNames))
		for _, name := range resourceNames {
			if policy, ok := resources.NetworkPolicies[name]; ok {
				policies[name] = policy
			}
		}
	}

	// Key by IP address to match the old implementation's contract.
	// Callers expect map keys to be endpoint IP addresses, not endpoint IDs.
	result := make(map[string]*cilium.NetworkPolicy, len(policies))
	for _, policy := range policies {
		for _, ip := range policy.EndpointIps {
			result[ip] = policy
		}
	}
	return result, nil
}

// portAllocationCallback returns a callback that fires all PortAllocationCallbacks on success.
// This is used to confirm port allocations after Envoy ACKs the listener update.
func (s *adsServer) portAllocationCallback(ctx context.Context, callbacks map[string]func(context.Context) error) func(err error) {
	if len(callbacks) == 0 {
		return nil
	}
	return func(err error) {
		if err != nil {
			return
		}
		for name, cb := range callbacks {
			if cb != nil {
				if callbackErr := cb(ctx); callbackErr != nil {
					s.logger.Warn(
						"Failure in port allocation callback",
						logfields.ListenerName, name,
						logfields.Error, callbackErr,
					)
				}
			}
		}
	}
}

// resourceUpdate retains the exact generation-fenced revert registered with
// the cache. UpdateNetworkPolicy uses it for endpoint regeneration rollback,
// so the NACK and caller-driven paths cannot construct competing inverses.
type resourceUpdate struct {
	updated    bool
	revertFunc xdsnew.RevertFunc
}

// Generation zero is never published. It asks a revert to use the node's
// current generation for caller-driven rollback after a successful ACK.
const revertCurrentGeneration uint64 = 0

func (u resourceUpdate) changed() bool {
	return u.updated
}

func (u resourceUpdate) revert() {
	if u.revertFunc != nil {
		_, _ = u.revertFunc(revertCurrentGeneration)
	}
}

// buildRevert captures the inverse sparse mutation and returns a closure that
// restores it. The caller threads the actual generation returned by one
// successful revert into the next older revert. A revert is skipped if the
// current generation no longer matches that rollback chain. Replaying the
// same revert is successful without publishing another resource generation;
// this lets a later NACK continue rolling back older coalesced updates after an
// endpoint regeneration has already reverted this update.
// Caller must hold s.mutex.
func (s *adsServer) buildRevert(ctx context.Context, nodeID string, pushedGeneration uint64, mutations xdsnew.ResourceMutations) xdsnew.RevertFunc {
	var revertedExpectedGeneration, revertedGeneration uint64

	return func(expectedGeneration uint64) (uint64, bool) {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		currentGeneration := s.resourceGenerations[nodeID]
		if revertedGeneration != 0 {
			if expectedGeneration == revertCurrentGeneration {
				return currentGeneration, true
			}
			return currentGeneration, expectedGeneration == revertedExpectedGeneration && currentGeneration == revertedGeneration
		}
		if expectedGeneration == revertCurrentGeneration {
			expectedGeneration = currentGeneration
		}

		// Check whether the resource state is still the generation expected by
		// the rollback chain. The newest changed update normally expects its own
		// pushedGeneration; a newer no-op completion may advance that expectation.
		// Each successful revert publishes a fresh generation which is threaded
		// into the next older revert.
		if currentGeneration != expectedGeneration {
			s.logger.Info(
				"Skipping revert, resource generation has been superseded",
				logfields.NodeID, nodeID,
				logfields.XDSPushedGeneration, pushedGeneration,
				logfields.XDSExpectedGeneration, expectedGeneration,
				logfields.XDSCurrentGeneration, currentGeneration,
			)
			return currentGeneration, false
		}

		s.logger.Info("Reverting snapshot for node", logfields.NodeID, nodeID)
		update, err := s.applyResourceUpdate(ctx, nodeID, mutations, nil, nil)
		if err != nil {
			s.logger.Error("Failed to revert snapshot",
				logfields.NodeID, nodeID,
				logfields.Error, err)
			return s.resourceGenerations[nodeID], false
		}
		revertedExpectedGeneration = expectedGeneration
		revertedGeneration = s.resourceGenerations[nodeID]
		return revertedGeneration, update.changed() || revertedGeneration == expectedGeneration
	}
}

// applyResourceUpdate forwards sparse mutation intent to the cache, which is
// the authority for semantic equality, copy-on-write, and changed TypeURLs.
// Caller must hold s.mutex.
func (s *adsServer) applyResourceUpdate(ctx context.Context, nodeID string, mutations xdsnew.ResourceMutations, wg *completion.WaitGroup, callbackTypeURLs map[string]func(error)) (resourceUpdate, error) {
	if nodeID == "" {
		nodeID = localNodeID
	}
	newGeneration := s.resourceGeneration + 1
	revertFactory := func(inverse xdsnew.ResourceMutations) xdsnew.RevertFunc {
		return s.buildRevert(ctx, nodeID, newGeneration, inverse)
	}
	updated, revertFunc, err := s.cache.ApplyResources(ctx, nodeID, newGeneration, mutations, wg, callbackTypeURLs, revertFactory)
	if err != nil {
		return resourceUpdate{}, err
	}
	if updated {
		s.resourceGeneration = newGeneration
		s.resourceGenerations[nodeID] = newGeneration
	} else {
		s.logger.Debug("ADS resources are identical, skipping update")
	}
	if updated && nodeID == localNodeID && (len(mutations.Removed.Listeners) > 0 || len(mutations.Upserted.Listeners) > 0) {
		s.syncNPDSListeners(s.cache.GetAllResources(nodeID))
	}
	return resourceUpdate{updated: updated, revertFunc: revertFunc}, nil
}

// syncNPDSListeners updates the ADS NetworkPolicy ACK expectation from the
// listeners in the local Envoy snapshot. Caller must hold s.mutex.
func (s *adsServer) syncNPDSListeners(resources *xds.Resources) {
	hadNPDSListeners := !s.npdsListeners.Empty()
	npdsListeners := make(npdsListenersTracker)
	if resources != nil {
		for name, listener := range resources.Listeners {
			if listenerRequiresNPDS(listener) {
				npdsListeners[name] = struct{}{}
			}
		}
	}
	s.npdsListeners = npdsListeners

	if hadNPDSListeners && s.npdsListeners.Empty() {
		s.cache.GetCompletionCallbacks().CancelPendingCompletions(NetworkPolicyTypeURL)
	}
}

func (s *adsServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources, wg *completion.WaitGroup) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	var callbackTypeURLs map[string]func(error)
	if callback != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: callback}
		if len(resources.Clusters) > 0 {
			callbackTypeURLs[ClusterTypeURL] = nil
		}
	}
	_, err := s.applyResourceUpdate(ctx, localNodeID, xdsnew.ResourceMutations{Upserted: resources}, wg, callbackTypeURLs)
	return err
}

func (s *adsServer) UpdateEnvoyResources(ctx context.Context, oldResources, newResources xds.Resources, waitGroup *completion.WaitGroup) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	hadPortAllocationCallbacks := len(newResources.PortAllocationCallbacks) > 0
	// If a listener exists in both old and new with the same port, the port allocation
	// was already acked - remove the callback to avoid double-acking.
	for _, oldListener := range oldResources.Listeners {
		oldPort := uint32(0)
		if addr := oldListener.Address.GetSocketAddress(); addr != nil {
			oldPort = addr.GetPortValue()
		}
		for _, newListener := range newResources.Listeners {
			if newListener.Name == oldListener.Name {
				if addr := newListener.Address.GetSocketAddress(); addr != nil && addr.GetPortValue() == oldPort {
					// Port is not changing, remove callback to prevent acking an already acked port.
					delete(newResources.PortAllocationCallbacks, newListener.Name)
				}
				break
			}
		}
	}

	callback := s.portAllocationCallback(ctx, newResources.PortAllocationCallbacks)
	var callbackTypeURLs map[string]func(error)
	if hadPortAllocationCallbacks {
		// CEC updates pass a wait group only to observe dynamic listener port
		// allocation. If the callbacks were removed because the listener port did
		// not change, do not fall back to waiting for every changed ADS type:
		// CDS/RDS ACKs can be delayed by dependent EDS/SDS resources and block
		// later CEC updates behind an already-confirmed port.
		callbackTypeURLs = map[string]func(error){}
	}
	if callback != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: callback}
		if len(oldResources.Clusters) > 0 || len(newResources.Clusters) > 0 {
			callbackTypeURLs[ClusterTypeURL] = nil
		}
	}
	_, err := s.applyResourceUpdate(ctx, localNodeID, xdsnew.ResourceMutations{Removed: oldResources, Upserted: newResources}, waitGroup, callbackTypeURLs)
	return err
}

func (s *adsServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources, waitGroup *completion.WaitGroup) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.logger.Debug(
		"DeleteEnvoyResources: Deleting Envoy resources",
		logfields.ResourceListeners, len(resources.Listeners),
		logfields.ResourceRoutes, len(resources.Routes),
		logfields.ResourceClusters, len(resources.Clusters),
		logfields.ResourceEndpoints, len(resources.Endpoints),
		logfields.ResourceSecrets, len(resources.Secrets),
	)

	var callbackTypeURLs map[string]func(error)
	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	if callback != nil {
		if callbackTypeURLs == nil {
			callbackTypeURLs = map[string]func(error){}
		}
		callbackTypeURLs[ListenerTypeURL] = callback
	}
	_, err := s.applyResourceUpdate(ctx, localNodeID, xdsnew.ResourceMutations{Removed: resources}, waitGroup, callbackTypeURLs)
	return err
}

func (s *adsServer) getNetworkPolicy(ep endpoint.EndpointUpdater, getEgressNamedPorts GetEgressNamedPorts, selectors policy.SelectorSnapshot, names []string, l4Policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext, useSDS bool, policySecretsNamespace string,
) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		EndpointIps: names,
		EndpointId:  ep.GetID(),
	}

	if l4Policy != nil {
		p.IngressPerPortPolicies = GetDirectionNetworkPolicy(ep, getEgressNamedPorts, selectors, &l4Policy.Ingress, ingressPolicyEnforced, useFullTLSContext, useSDS, ingressDirection, policySecretsNamespace, s.logger, s.l7RulesTranslator)
		p.EgressPerPortPolicies = GetDirectionNetworkPolicy(ep, getEgressNamedPorts, selectors, &l4Policy.Egress, egressPolicyEnforced, useFullTLSContext, useSDS, egressDirection, policySecretsNamespace, s.logger, s.l7RulesTranslator)
	}

	return p
}
