// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"

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
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
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

	// npdsListenerCount is the number of local-node listeners which start an NPDS
	// client. The cache updates it atomically from exact committed listener
	// transitions, so NetworkPolicy updates only need a lock-free zero check.
	npdsListenerCount atomic.Int64

	// proxyListeners is the count of redirection proxy listeners in 'listeners'.
	// This value is different from len(listeners) due to non-proxy listeners
	// (e.g., prometheus listener)
	proxyListeners int

	// listenerCount is the set of names of listeners that have been added by
	// calling addListener.
	// mutex must be held when accessing this.
	// Value holds the number of redirects using the listener named by the key.
	listenerCount map[string]uint

	// stopFunc contains the function which stops the xDS gRPC server.
	stopFunc context.CancelFunc

	// IPCache is used for tracking IP->Identity mappings and propagating
	// them to the proxy via NPHDS in the cases described
	ipCache IPCacheEventSource

	localEndpointStore *LocalEndpointStore

	l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator
	secretManager     certificatemanager.SecretManager

	// restorerPromise is cleared when restoration finishes. A non-nil value also
	// suppresses ACK/NACK waits while the cache is populated before the ADS server
	// starts serving. mutex must be held during access after construction.
	restorerPromise promise.Promise[endpointstate.Restorer]
}

func newADSServerWithCache(cache xdsnew.Cache, logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	adsServer := &adsServer{
		logger:             logger,
		cache:              cache,
		ipCache:            ipCache,
		localEndpointStore: localEndpointStore,
		config:             config,
		secretManager:      secretManager,
		socketPath:         util.GetXDSSocketPath(config.envoySocketDir),
		accessLogPath:      util.GetAccessLogSocketPath(config.envoySocketDir),
		restorerPromise:    restorerPromise,
		listenerCount:      make(map[string]uint),
	}
	cache.SetListenerObserver(
		localNodeID,
		adsServer.updateNPDSListenerCount,
		adsServer.cancelNetworkPolicyCompletionsWithoutNPDSListeners,
	)
	return adsServer
}

// newADSServer creates a new ADS GRPC server.
func newADSServer(logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	return newADSServerWithCache(xdsnew.NewCache(logger, config.envoyXDSMode.IsStrictADS()), logger, ipCache, localEndpointStore, config, secretManager, restorerPromise)
}

func (s *adsServer) run(ctx context.Context) error {
	return s.startAdsGRPCServer(ctx)
}

func (s *adsServer) markRestoreCompleted() {
	s.mutex.Lock()
	s.restorerPromise = nil
	s.mutex.Unlock()
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

	update, err := s.upsertListenerResource(ctx, localNodeID, name, listenerConfig, wg, cb)
	if err != nil {
		return err
	}
	update.finalize()
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

func (s *adsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) {
	s.removeListener(ctx, name, wg, true)
}

// removeListener removes an existing Envoy Listener.
// The listener is only actually deleted when the reference count reaches zero.
func (s *adsServer) removeListener(ctx context.Context, name string, wg *completion.WaitGroup, isProxyListener bool) {
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
		return
	}

	count--
	if count > 0 {
		// Other redirects still using this listener, just decrement.
		s.listenerCount[name] = count
		return
	}

	// count == 0: actually delete the listener.
	if isProxyListener {
		s.proxyListeners--
	}
	delete(s.listenerCount, name)

	// Cancel all pending network policy completions if this was the last
	// proxy listener, since Envoy will never ACK them.
	if isProxyListener && s.proxyListeners == 0 {
		s.cache.GetCompletionCallbacks().CancelPendingCompletions(typeurl.NetworkPolicy)
	}

	s.logger.Info(
		"Envoy: Deleting listener",
		logfields.Listener, name,
	)

	// The cache owns the generation-fenced revert used if Envoy NACKs the
	// listener removal. RemoveListener does not expose caller-driven rollback.
	update, _ := s.removeListenerResource(ctx, localNodeID, name, wg, nil)
	update.finalize()
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
			update, _ := s.removeNetworkPolicyResource(ctx, localNodeID, dupName, nil, nil)
			update.finalize()
		}
	}

	networkPolicy := s.getNetworkPolicy(ep, epp.SelectorPolicy.GetEgressNamedPorts, selectors, names, l4policy, ingressPolicyEnforced, egressPolicyEnforced, s.config.useFullTLSContext, s.config.useSDS, s.secretManager.GetSecretSyncNamespace())

	// First, validate the policy
	err := networkPolicy.Validate()
	if err != nil {
		return fmt.Errorf("error validating generated NetworkPolicy for %d/%s: %w", ep.GetID(), ep.GetPolicyNames(), err), nil, nil
	}

	epID := ep.GetID()
	resourceName := strconv.FormatUint(epID, 10)

	// If there are no listeners configured that start an NPDS client, the local
	// node's Envoy proxy won't query for network policies and therefore will
	// never ACK them, and we'd wait forever.
	waitForACK := wg != nil && s.restorerPromise == nil && s.hasNPDSListeners()
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
	var updateCallback func(error)
	if waitForACK {
		updateCallback = callback
	}
	update, err := s.upsertNetworkPolicyResource(ctx, LocalNodeID, resourceName, networkPolicy, wg, updateCallback)
	if err != nil {
		return err, nil, nil
	}
	if waitForACK {
		// The last NPDS listener can disappear after the check above, with its
		// cancellation completing before this cache mutation registers its wait.
		// Recheck after registration to close that gap. If the listener disappears
		// later, the cache's Listener observer performs the cancellation instead.
		s.cancelNetworkPolicyCompletionsWithoutNPDSListeners()
	}
	if update.changed() {
		resourceUpdates = append(resourceUpdates, update)
	}

	if !waitForACK {
		callback(nil)
	}

	return nil, func() error {
			s.logger.Debug("Reverting xDS network policy update")

			// A cache-owned NACK may already have restored this update. The
			// resource-generation fence makes the caller-owned revert harmless then.
			for _, update := range resourceUpdates {
				update.revert()
			}
			s.logger.Debug("Finished reverting xDS network policy update")
			return nil
		}, func() {
			if s.logger.Enabled(context.Background(), slog.LevelDebug) {
				s.logger.Debug("Finalizing xDS network policy update",
					logfields.EndpointID, epID,
				)
			}
			for _, update := range resourceUpdates {
				update.finalize()
			}
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

	update, _ := s.removeNetworkPolicyResource(ctx, localNodeID, resourceName, nil, nil)
	update.finalize()
}

func (s *adsServer) RemoveAllNetworkPolicies() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	policies := maps.Collect(s.cache.NetworkPolicies(localNodeID))
	if len(policies) == 0 {
		return
	}
	mutations := xdsnew.ResourceMutations{Removed: xds.Resources{NetworkPolicies: policies}}
	update, err := s.applyResourceUpdate(context.Background(), localNodeID, mutations, nil, xdsnew.TypeURLCallbacks{})
	if err != nil {
		s.logger.Error("Failed to remove all network policies", logfields.Error, err)
		return
	}
	update.finalize()
}

func (s *adsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var policies map[string]*cilium.NetworkPolicy
	if len(resourceNames) > 0 {
		policies = make(map[string]*cilium.NetworkPolicy, len(resourceNames))
		for _, name := range resourceNames {
			resource, ok := s.cache.GetResource(localNodeID, typeurl.NetworkPolicy, name)
			if policy, typeOK := resource.(*cilium.NetworkPolicy); ok && typeOK {
				policies[name] = policy
			}
		}
	} else {
		for name, policy := range s.cache.NetworkPolicies(localNodeID) {
			if policies == nil {
				policies = make(map[string]*cilium.NetworkPolicy)
			}
			policies[name] = policy
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

// resourceUpdate retains the caller-owned, resource-generation-fenced terminal
// operations returned by the cache. Cache-owned NACK rollback has an
// independent lifetime so endpoint regeneration can finalize its ownership
// without weakening protocol rollback.
type resourceUpdate struct {
	updated      bool
	revertFunc   xdsnew.RevertFunc
	finalizeFunc xdsnew.FinalizeFunc
}

// No resource update uses generation zero. It identifies caller-driven
// rollback rather than an xDS NACK rollback chain; the cache may use zero for
// an initial empty snapshot which has no resource update to revert.
const revertCurrentGeneration uint64 = 0

func (u resourceUpdate) changed() bool {
	return u.updated
}

func (u resourceUpdate) revert() {
	if u.revertFunc != nil {
		_, _ = u.revertFunc(revertCurrentGeneration)
	}
}

func (u resourceUpdate) finalize() {
	if u.finalizeFunc != nil {
		u.finalizeFunc()
	}
}

func (s *adsServer) finishResourceUpdate(updated bool, revertFunc xdsnew.RevertFunc, finalizeFunc xdsnew.FinalizeFunc, err error) (resourceUpdate, error) {
	if err != nil {
		return resourceUpdate{}, err
	}
	if !updated && s.logger.Enabled(context.Background(), slog.LevelDebug) {
		s.logger.Debug("ADS resources are identical, skipping update")
	}
	return resourceUpdate{updated: updated, revertFunc: revertFunc, finalizeFunc: finalizeFunc}, nil
}

func (s *adsServer) upsertListenerResource(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (resourceUpdate, error) {
	completeImmediately := s.restorerPromise != nil && wg != nil
	if completeImmediately {
		wg = nil
	}
	updated, revertFunc, finalizeFunc, err := s.cache.UpsertListener(ctx, nodeID, name, resource, wg, callback)
	update, err := s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
	if completeImmediately && err == nil && callback != nil {
		callback(nil)
	}
	return update, err
}

func (s *adsServer) removeListenerResource(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (resourceUpdate, error) {
	completeImmediately := s.restorerPromise != nil && wg != nil
	if completeImmediately {
		wg = nil
	}
	updated, revertFunc, finalizeFunc, err := s.cache.RemoveListener(ctx, nodeID, name, wg, callback)
	update, err := s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
	if completeImmediately && err == nil && callback != nil {
		callback(nil)
	}
	return update, err
}

func (s *adsServer) upsertNetworkPolicyResource(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (resourceUpdate, error) {
	updated, revertFunc, finalizeFunc, err := s.cache.UpsertNetworkPolicy(ctx, nodeID, name, resource, wg, callback)
	return s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
}

func (s *adsServer) removeNetworkPolicyResource(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (resourceUpdate, error) {
	updated, revertFunc, finalizeFunc, err := s.cache.RemoveNetworkPolicy(ctx, nodeID, name, wg, callback)
	return s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
}

func (s *adsServer) upsertNetworkPolicyHostsResource(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (resourceUpdate, error) {
	updated, revertFunc, finalizeFunc, err := s.cache.UpsertNetworkPolicyHosts(ctx, nodeID, name, resource)
	return s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
}

func (s *adsServer) removeNetworkPolicyHostsResource(ctx context.Context, nodeID, name string) (resourceUpdate, error) {
	updated, revertFunc, finalizeFunc, err := s.cache.RemoveNetworkPolicyHosts(ctx, nodeID, name)
	return s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
}

// applyResourceUpdate forwards sparse mutation intent to the cache, which is
// the authority for semantic equality, changed resource names, published
// copy-on-write snapshots, and generation-fenced reverts.
// Caller must hold s.mutex.
func (s *adsServer) applyResourceUpdate(ctx context.Context, nodeID string, mutations xdsnew.ResourceMutations, wg *completion.WaitGroup, callbackTypeURLs xdsnew.TypeURLCallbacks) (resourceUpdate, error) {
	restoring := s.restorerPromise != nil
	callbacks := callbackTypeURLs
	if restoring {
		wg = nil
		// An explicitly empty set prevents the cache from inferring an LDS wait.
		callbackTypeURLs = xdsnew.NewTypeURLCallbacks()
	}
	updated, revertFunc, finalizeFunc, err := s.cache.ApplyResources(ctx, nodeID, mutations, wg, callbackTypeURLs)
	update, err := s.finishResourceUpdate(updated, revertFunc, finalizeFunc, err)
	if restoring && err == nil {
		for _, callback := range callbacks.All() {
			if callback != nil {
				callback(nil)
			}
		}
	}
	return update, err
}

// updateNPDSListenerCount updates server-derived listener state while the
// cache transaction is still serialized. Its return value requests a callback
// after unlock when the transition removed the last NPDS listener.
func (s *adsServer) updateNPDSListenerCount(changes []xdsnew.ListenerChange) bool {
	var delta int64
	for _, change := range changes {
		if listenerRequiresNPDS(change.Previous) {
			delta--
		}
		if listenerRequiresNPDS(change.Current) {
			delta++
		}
	}
	if delta == 0 {
		return false
	}
	return s.npdsListenerCount.Add(delta) == 0
}

func (s *adsServer) hasNPDSListeners() bool {
	return s.npdsListenerCount.Load() > 0
}

func (s *adsServer) cancelNetworkPolicyCompletionsWithoutNPDSListeners() {
	if !s.hasNPDSListeners() {
		s.cache.GetCompletionCallbacks().CancelPendingCompletions(typeurl.NetworkPolicy)
	}
}

func adsListenerReusePortDisabled(listener *envoy_config_listener.Listener) bool {
	reusePort := listener.GetEnableReusePort()
	return reusePort != nil && !reusePort.GetValue()
}

func adsListenersRequiringRecreate(oldListeners, newListeners map[string]*envoy_config_listener.Listener) []string {
	var names []string
	for name, oldListener := range oldListeners {
		newListener, found := newListeners[name]
		if found && !listenerAddressesEqual(oldListener, newListener) &&
			(adsListenerReusePortDisabled(oldListener) || adsListenerReusePortDisabled(newListener)) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func referencedRouteNames(listeners map[string]*envoy_config_listener.Listener) map[string]struct{} {
	referenced := make(map[string]struct{})
	for _, listener := range listeners {
		for _, filterChain := range listener.GetFilterChains() {
			for _, filter := range filterChain.GetFilters() {
				typedConfig := filter.GetTypedConfig()
				if typedConfig == nil {
					continue
				}
				message, err := typedConfig.UnmarshalNew()
				if err != nil {
					continue
				}
				hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
				if !ok {
					continue
				}
				if name := hcm.GetRds().GetRouteConfigName(); name != "" {
					referenced[name] = struct{}{}
				}
			}
		}
	}
	return referenced
}

// listenerDeletionMutations builds the intermediate accepted state without the
// listeners whose addresses are changing. The cache remains the owner of
// desired resources; only the sparse entries touched by this CEC update and any
// temporarily unreferenced strict-ADS routes are materialized.
func (s *adsServer) listenerDeletionMutations(oldResources, newResources xds.Resources, listenerNames []string) (staged xdsnew.ResourceMutations) {
	staged.Removed = newResources
	staged.Upserted = oldResources
	staged.Upserted.Listeners = maps.Clone(oldResources.Listeners)
	for _, name := range listenerNames {
		delete(staged.Upserted.Listeners, name)
	}

	if !s.config.envoyXDSMode.IsStrictADS() {
		return staged
	}

	remainingListeners := maps.Collect(s.cache.Listeners(localNodeID))
	for _, name := range listenerNames {
		delete(remainingListeners, name)
	}
	referencedRoutes := referencedRouteNames(remainingListeners)

	staged.Removed.Routes = maps.Clone(newResources.Routes)
	if staged.Removed.Routes == nil {
		staged.Removed.Routes = make(map[string]*envoy_config_route.RouteConfiguration)
	}
	staged.Upserted.Routes = maps.Clone(oldResources.Routes)
	for name, route := range s.cache.Routes(localNodeID) {
		if _, referenced := referencedRoutes[name]; referenced {
			continue
		}
		staged.Removed.Routes[name] = route
		delete(staged.Upserted.Routes, name)
	}
	return staged
}

func (s *adsServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources, wg *completion.WaitGroup) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	var callbackTypeURLs xdsnew.TypeURLCallbacks
	if callback != nil {
		callbackTypeURLs.Set(typeurl.Listener, callback)
		if len(resources.Clusters) > 0 {
			callbackTypeURLs.Set(typeurl.Cluster, nil)
		}
	}
	update, err := s.applyResourceUpdate(ctx, localNodeID, xdsnew.ResourceMutations{Upserted: resources}, wg, callbackTypeURLs)
	update.finalize()
	return err
}

func (s *adsServer) UpdateEnvoyResources(ctx context.Context, oldResources, newResources xds.Resources, waitGroup *completion.WaitGroup) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	hadPortAllocationCallbacks := len(newResources.PortAllocationCallbacks) > 0
	listenersToRecreate := adsListenersRequiringRecreate(oldResources.Listeners, newResources.Listeners)
	// Port allocation applies only to the primary listener address. If its port
	// is unchanged, remove the callback to avoid acknowledging it again.
	for name, oldListener := range oldResources.Listeners {
		newListener, found := newResources.Listeners[name]
		if !found {
			continue
		}

		oldAddress := oldListener.GetAddress().GetSocketAddress()
		newAddress := newListener.GetAddress().GetSocketAddress()
		if oldAddress != nil && newAddress != nil &&
			oldAddress.GetPortValue() == newAddress.GetPortValue() {
			delete(newResources.PortAllocationCallbacks, name)
		}
	}

	callback := s.portAllocationCallback(ctx, newResources.PortAllocationCallbacks)
	var callbackTypeURLs xdsnew.TypeURLCallbacks
	if hadPortAllocationCallbacks {
		// CEC updates pass a wait group only to observe dynamic listener port
		// allocation. If the callbacks were removed because the listener port did
		// not change, do not fall back to waiting for every changed ADS type:
		// CDS/RDS ACKs can be delayed by dependent EDS/SDS resources and block
		// later CEC updates behind an already-confirmed port.
		callbackTypeURLs = xdsnew.NewTypeURLCallbacks()
	}
	if callback != nil {
		callbackTypeURLs.Set(typeurl.Listener, callback)
		if len(oldResources.Clusters) > 0 || len(newResources.Clusters) > 0 {
			callbackTypeURLs.Set(typeurl.Cluster, nil)
		}
	}
	if len(listenersToRecreate) == 0 || s.restorerPromise != nil {
		update, err := s.applyResourceUpdate(ctx, localNodeID, xdsnew.ResourceMutations{Removed: oldResources, Upserted: newResources}, waitGroup, callbackTypeURLs)
		update.finalize()
		return err
	}

	// Envoy cannot replace a listener's address set in place when SO_REUSEPORT
	// is disabled, because the replacement overlaps sockets still owned by the
	// active listener. Publish and ACK a snapshot without the listener first so
	// Envoy closes those sockets before the replacement is sent.
	stagedMutations := s.listenerDeletionMutations(oldResources, newResources, listenersToRecreate)
	// ACK waits observe the caller's deadline, but cache mutations and their
	// caller-owned rollback operations must remain usable after that deadline.
	mutationCtx := context.WithoutCancel(ctx)
	applyUpdate := func(mutations xdsnew.ResourceMutations, wg *completion.WaitGroup, callbacks xdsnew.TypeURLCallbacks) (resourceUpdate, error) {
		return s.applyResourceUpdate(mutationCtx, localNodeID, mutations, wg, callbacks)
	}

	s.logger.Debug("UpdateEnvoyResources: deleting listeners before address change",
		logfields.ResourcesDeleted, len(listenersToRecreate))
	deleteWG := completion.NewWaitGroup(ctx)
	var listenerWait xdsnew.TypeURLCallbacks
	listenerWait.Set(typeurl.Listener, nil)
	deleteUpdate, err := applyUpdate(stagedMutations, deleteWG, listenerWait)
	if err != nil {
		return err
	}
	if err := deleteWG.Wait(); err != nil {
		deleteUpdate.revert()
		return fmt.Errorf("waiting for listener deletion ACK: %w", err)
	}

	// Always wait for the replacement LDS ACK, even when the caller did not
	// supply a wait group. This keeps the two snapshots transactional and lets us
	// restore the last working listener if Envoy rejects the replacement.
	callbackTypeURLs.Set(typeurl.Listener, callback)
	replaceMutations := xdsnew.ResourceMutations{Removed: oldResources, Upserted: newResources}
	for attempt := 1; ; attempt++ {
		replaceWG := completion.NewWaitGroup(ctx)
		replaceUpdate, err := applyUpdate(replaceMutations, replaceWG, callbackTypeURLs)
		if err == nil {
			err = replaceWG.Wait()
		}
		if err == nil {
			replaceUpdate.finalize()
			deleteUpdate.finalize()
			return nil
		}
		// If Envoy NACKed the replacement, cache-owned rollback has already
		// restored this phase. On timeout, the caller-owned rollback does it now.
		// Either way, the generation fence makes this operation safe and leaves
		// the accepted listener-deletion state ready for a retry or full rollback.
		replaceUpdate.revert()

		if !isAddressAlreadyInUseError(err) || attempt >= listenerAddressChangeMaxAttempts {
			deleteUpdate.revert()
			return fmt.Errorf("waiting for replacement listener ACK: %w", err)
		}

		// Cache-owned NACK rollback has restored the accepted deletion state. A
		// subsequent watch finalizes that state before the replacement is retried,
		// allowing the same desired content version to be sent in a fresh response.
		s.logger.Debug("UpdateEnvoyResources: Retrying ADS listener address change after bind failure",
			logfields.Attempt, attempt+1,
			logfields.Error, err)
		timer := time.NewTimer(listenerAddressChangeRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			deleteUpdate.revert()
			return ctx.Err()
		case <-timer.C:
		}
	}
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

	var callbackTypeURLs xdsnew.TypeURLCallbacks
	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	if callback != nil {
		callbackTypeURLs.Set(typeurl.Listener, callback)
	}
	update, err := s.applyResourceUpdate(ctx, localNodeID, xdsnew.ResourceMutations{Removed: resources}, waitGroup, callbackTypeURLs)
	update.finalize()
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
