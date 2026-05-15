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
	"strconv"

	cilium "github.com/cilium/proxy/go/cilium/api"
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

var CiliumAdsConfigSource = &envoy_config_core.ApiConfigSource{
	RequestTimeout:            &durationpb.Duration{Seconds: 30},
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
}

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
		npdsListeners:      make(npdsListenersTracker),
	}
	return adsServer
}

// newADSServer creates a new ADS GRPC server.
func newADSServer(logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	return newADSServerWithCache(xdsnew.NewCache(logger), logger, ipCache, localEndpointStore, config, secretManager, restorerPromise)
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

	resources := s.cache.GetAllResources(localNodeID)

	if resources == nil {
		s.logger.Warn(fmt.Sprintf("Failed to get existing resources for node %s, creating new one", localNodeID))
		resources = &xds.Resources{
			Listeners: make(map[string]*envoy_config_listener.Listener),
		}
	} else {
		resources = resources.DeepCopy()
	}
	oldListener, existed := resources.Listeners[name]
	resources.Listeners[name] = listenerConfig
	var callbackTypeURLs map[string]func(error)
	if cb != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: cb}
	}
	return s.updateSnapshot(ctx, resources, localNodeID, wg, callbackTypeURLs,
		&resourceChanges{listeners: []savedEntry[*envoy_config_listener.Listener]{{key: name, value: oldListener, existed: existed}}})
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
			GetListenerFilter(isIngress, mayUseOriginalSourceAddr, port, lingerConfig),
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
	oldListener, existed := resources.Listeners[name]
	resources = resources.DeepCopy()
	delete(resources.Listeners, name)

	var changes *resourceChanges
	if wg != nil {
		changes = &resourceChanges{listeners: []savedEntry[*envoy_config_listener.Listener]{{key: name, value: oldListener, existed: existed}}}
	}
	// todo(nezdolik) pass update type urls when listeners are completely deleted
	s.updateSnapshot(ctx, resources, localNodeID, wg, nil, changes)

	return func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		if existed {
			s.logger.Debug("Reverting listener removal", logfields.Listener, name)
			resources := s.cache.GetAllResources(localNodeID)
			resources.Listeners[name] = oldListener
			s.updateSnapshot(ctx, resources, localNodeID, nil, nil, nil)
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
			resources := s.cache.GetAllResources(localNodeID)
			if resources != nil {
				if _, exists := resources.NetworkPolicies[dupName]; exists {
					resources = resources.DeepCopy()
					delete(resources.NetworkPolicies, dupName)
					s.updateSnapshot(ctx, resources, localNodeID, nil, nil, nil)
				}
			}
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

	// Capture old local endpoint state for revert.
	revertEndpoints := make(map[string]endpoint.EndpointUpdater, len(names))
	for _, name := range names {
		revertEndpoints[name] = s.localEndpointStore.getLocalEndpoint(name)
		s.localEndpointStore.setLocalEndpoint(ep)
	}

	for _, nodeId := range nodeIDs {
		resources := s.cache.GetAllResources(nodeId)
		if resources == nil {
			resources = &xds.Resources{}
		}
		resources = resources.DeepCopy()
		oldPolicy, existed := resources.NetworkPolicies[resourceName]
		resources.NetworkPolicies[resourceName] = networkPolicy
		var callbackTypeURLs map[string]func(error)
		if waitForACK {
			callbackTypeURLs = map[string]func(error){NetworkPolicyTypeURL: callback}
		}
		if err := s.updateSnapshot(ctx, resources, nodeId, wg, callbackTypeURLs,
			&resourceChanges{networkPolicies: []savedEntry[*cilium.NetworkPolicy]{{key: resourceName, value: oldPolicy, existed: existed}}}); err != nil {
			return err, nil, nil
		}
	}
	if !waitForACK {
		callback(nil)
	}

	return nil, func() error {
			s.logger.Debug("Reverting xDS network policy update")

			s.mutex.Lock()
			defer s.mutex.Unlock()

			// Restore local endpoint mappings.
			for _, oldEp := range revertEndpoints {
				if oldEp == nil {
					s.localEndpointStore.removeLocalEndpoint(ep)
				} else {
					s.localEndpointStore.setLocalEndpoint(ep)
				}
			}

			// Remove the policy we just added and re-push snapshot.
			for _, nodeId := range nodeIDs {
				resources := s.cache.GetAllResources(nodeId)
				if resources == nil {
					continue
				}
				resources = resources.DeepCopy()
				oldPolicy, existed := resources.NetworkPolicies[resourceName]
				delete(resources.NetworkPolicies, resourceName)
				changes := &resourceChanges{
					networkPolicies: []savedEntry[*cilium.NetworkPolicy]{{
						key:     resourceName,
						value:   oldPolicy,
						existed: existed,
					}},
				}
				if err := s.updateSnapshot(ctx, resources, nodeId, nil, nil, changes); err != nil {
					return err
				}
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

	// Host proxy uses "127.0.0.1" as the nodeID
	resources := s.cache.GetAllResources(localNodeID)
	if resources == nil {
		return
	}
	// Work on a copy so the cached state is untouched.
	resources = resources.DeepCopy()
	oldPolicy, existed := resources.NetworkPolicies[resourceName]
	delete(resources.NetworkPolicies, resourceName)

	ip := ep.GetIPv6Address()
	if ip != "" {
		s.localEndpointStore.removeLocalEndpoint(ep)
	}
	ip = ep.GetIPv4Address()
	if ip != "" {
		s.localEndpointStore.removeLocalEndpoint(ep)
	}

	var changes *resourceChanges
	if existed {
		changes = &resourceChanges{
			networkPolicies: []savedEntry[*cilium.NetworkPolicy]{{
				key:     resourceName,
				value:   oldPolicy,
				existed: true,
			}},
		}
	}
	s.updateSnapshot(ctx, resources, localNodeID, nil, nil, changes)
}

func (s *adsServer) RemoveAllNetworkPolicies() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	resources := s.cache.GetAllResources(localNodeID)
	if resources == nil {
		return
	}
	newResources := resources.DeepCopy()
	newResources.NetworkPolicies = map[string]*cilium.NetworkPolicy{}

	if err := s.updateSnapshot(context.Background(), newResources, localNodeID, nil, nil, computeChanges(resources, newResources)); err != nil {
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

// resourceChanges captures the previous state of resources that are about to change.
// Each slice records the old value for keys being modified. Used by buildRevert to
// restore only the changed resources on NACK, instead of reverting the entire snapshot.
type resourceChanges struct {
	listeners          []savedEntry[*envoy_config_listener.Listener]
	routes             []savedEntry[*envoy_config_route.RouteConfiguration]
	clusters           []savedEntry[*envoy_config_cluster.Cluster]
	endpoints          []savedEntry[*envoy_config_endpoint.ClusterLoadAssignment]
	secrets            []savedEntry[*envoy_config_tls.Secret]
	networkPolicies    []savedEntry[*cilium.NetworkPolicy]
	networkPolicyHosts []savedEntry[*cilium.NetworkPolicyHosts]
}

// computeChanges builds a resourceChanges by diffing current and new resources.
func computeChanges(current, new *xds.Resources) *resourceChanges {
	if current == nil {
		current = &xds.Resources{}
	}
	return &resourceChanges{
		listeners:          diffMap(current.Listeners, new.Listeners),
		routes:             diffMap(current.Routes, new.Routes),
		clusters:           diffMap(current.Clusters, new.Clusters),
		endpoints:          diffMap(current.Endpoints, new.Endpoints),
		secrets:            diffMap(current.Secrets, new.Secrets),
		networkPolicies:    diffMap(current.NetworkPolicies, new.NetworkPolicies),
		networkPolicyHosts: diffMap(current.NetworkPolicyHosts, new.NetworkPolicyHosts),
	}
}

// buildRevert captures the given resource changes and returns a closure that
// restores them. The revert is skipped if another update has been applied since
// (detected via snapshot version mismatch).
// Caller must hold s.mutex.
func (s *adsServer) buildRevert(ctx context.Context, nodeID string, newResources *xds.Resources, changes *resourceChanges) func() {
	// Compute the version of the snapshot we are about to push so we can
	// detect whether a subsequent update has superseded ours.
	pushedVersion := s.cache.GetVersion(newResources)
	if changes == nil {
		changes = &resourceChanges{}
	}

	return func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		// Check whether the snapshot is still the one we pushed.
		currentResources := s.cache.GetAllResources(nodeID)
		currentVersion := s.cache.GetVersion(currentResources)
		if currentVersion != pushedVersion {
			s.logger.Info(
				"Skipping revert, snapshot has been superseded",
				logfields.NodeID, nodeID,
				logfields.XDSPushedVersion, pushedVersion,
				logfields.XDSCurrentVersion, currentVersion,
			)
			return
		}

		s.logger.Info("Reverting snapshot for node", logfields.NodeID, nodeID)
		// Work on a copy so we don't mutate cached state.
		reverted := currentResources.DeepCopy()
		applyDiff(reverted.Listeners, changes.listeners)
		applyDiff(reverted.Routes, changes.routes)
		applyDiff(reverted.Clusters, changes.clusters)
		applyDiff(reverted.Endpoints, changes.endpoints)
		applyDiff(reverted.Secrets, changes.secrets)
		applyDiff(reverted.NetworkPolicies, changes.networkPolicies)
		applyDiff(reverted.NetworkPolicyHosts, changes.networkPolicyHosts)

		revertChanges := computeChanges(currentResources, reverted)
		if err := s.updateSnapshot(ctx, reverted, nodeID, nil, nil, revertChanges); err != nil {
			s.logger.Error("Failed to revert snapshot",
				logfields.NodeID, nodeID,
				logfields.Error, err)
		}
	}
}

// savedEntry records the previous value of a single resource key.
// If existed is false, the key was not present before the update and should be deleted on revert.
type savedEntry[V any] struct {
	key     string
	value   V
	existed bool
}

// diffMap returns entries for every key whose value differs between old and new,
// plus keys present in old but absent in new (deletions). Keys that are identical
// in both maps are not saved.
func diffMap[V comparable](old, new map[string]V) []savedEntry[V] {
	var saved []savedEntry[V]
	// Keys that are new or changed.
	for k := range new {
		oldVal, existed := old[k]
		if !existed || any(oldVal) != any(new[k]) {
			saved = append(saved, savedEntry[V]{key: k, value: oldVal, existed: existed})
		}
	}
	// Keys deleted from old.
	for k, v := range old {
		if _, inNew := new[k]; !inNew {
			saved = append(saved, savedEntry[V]{key: k, value: v, existed: true})
		}
	}
	return saved
}

// applyDiff restores saved entries into dst.
func applyDiff[V any](dst map[string]V, entries []savedEntry[V]) {
	for _, e := range entries {
		if e.existed {
			dst[e.key] = e.value
		} else {
			delete(dst, e.key)
		}
	}
}

// Caller must hold s.mutex.
func (s *adsServer) updateSnapshot(ctx context.Context, resources *xds.Resources, nodeId string, wg *completion.WaitGroup, callbackTypeURLs map[string]func(err error), changes *resourceChanges) error {
	if nodeId == "" {
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
		if len(resources.NetworkPolicies) > 0 {
			msg += fmt.Sprintf("%s%d network policies", sep, len(resources.NetworkPolicies))
			sep = ", "
		}
		if len(resources.NetworkPolicyHosts) > 0 {
			msg += fmt.Sprintf("%s%d network policy hosts", sep, len(resources.NetworkPolicyHosts))
		}

		s.logger.Debug(
			"updateXdsSnapshot: Updating Envoy resources",
			logfields.Resource, msg,
		)
	}
	for _, r := range resources.Secrets {
		s.logger.Debug(
			"Envoy updateSecret",
			logfields.ResourceName, r.Name,
		)
	}
	for _, r := range resources.Endpoints {
		s.logger.Debug(
			"Envoy updateEndpoint",
			logfields.ResourceName, r.ClusterName,
			logfields.Resource, r,
		)
	}
	for _, r := range resources.Clusters {
		s.logger.Debug(
			"Envoy updateCluster",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
	}
	for _, r := range resources.Routes {
		s.logger.Debug(
			"Envoy updateRoute",
			logfields.ResourceName, r.Name,
			logfields.Resource, r,
		)
	}

	updatedTypeURLsInSnapshot := getUpdatedTypeURLs(changes)
	// Callers can explicitly add type URLs when the changed type cannot be
	// inferred from the changed resource entries.
	if callbackTypeURLs != nil {
		if updatedTypeURLsInSnapshot == nil {
			updatedTypeURLsInSnapshot = callbackTypeURLs
		} else {
			maps.Copy(updatedTypeURLsInSnapshot, callbackTypeURLs)
		}
	}
	newSnapshot, err := s.cache.GenerateSnapshot(resources, s.logger)
	if err != nil {
		return err
	}
	oldSnapshot, _ := s.cache.GetSnapshot(nodeId)
	if oldSnapshot == nil {
		// This may be first update for this node, so snapshot may not exist yet.
		s.logger.Warn("Failed to get snapshot for node, will create new one",
			logfields.NodeID, nodeId)
	}

	if oldSnapshot == nil || len(updatedTypeURLsInSnapshot) > 0 || s.cache.AreDifferentSnapshots(oldSnapshot, newSnapshot) {
		var revertFunc func()
		if wg != nil {
			revertFunc = s.buildRevert(ctx, nodeId, resources, changes)
		}
		err = s.cache.UpdateSnapshot(ctx, nodeId, newSnapshot, wg, updatedTypeURLsInSnapshot, revertFunc)
		if err != nil {
			s.logger.Error("Error setting snapshot for node %s: %q",
				logfields.NodeID, nodeId,
				logfields.Error, err)
			return err
		} else {
			s.cache.SetResources(nodeId, resources)
		}
	} else {
		s.logger.Debug("updateXdsSnapshot: Snapshots are identical, skipping update")
	}

	if nodeId == localNodeID {
		s.syncNPDSListeners(resources)
	}

	return nil
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

	currentResources := s.cache.GetAllResources(localNodeID)
	if currentResources == nil {
		currentResources = &xds.Resources{}
	}
	// Merge new resources into a copy of current resources (upsert semantics).
	merged := currentResources.DeepCopy()
	mergeResources(merged, &resources)
	changes := computeChanges(currentResources, merged)

	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	var callbackTypeURLs map[string]func(error)
	if callback != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: callback}
	}
	return s.updateSnapshot(ctx, merged, "", wg, callbackTypeURLs, changes)
}

func (s *adsServer) UpdateEnvoyResources(ctx context.Context, oldResources, newResources xds.Resources, waitGroup *completion.WaitGroup) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If a listener exists in both old and new with the same port, the port allocation
	// was already acked — remove the callback to avoid double-acking.
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

	currentResources := s.cache.GetAllResources(localNodeID)
	if currentResources == nil {
		currentResources = &xds.Resources{}
	}
	// Subtract old resources and merge new resources (update semantics).
	updated := subtractResources(currentResources, &oldResources)
	mergeResources(&updated, &newResources)
	changes := computeChanges(currentResources, &updated)

	callback := s.portAllocationCallback(ctx, newResources.PortAllocationCallbacks)
	var callbackTypeURLs map[string]func(error)
	if callback != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: callback}
	}
	return s.updateSnapshot(ctx, &updated, "", waitGroup, callbackTypeURLs, changes)
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

	currentResources := s.cache.GetAllResources(localNodeID)
	if currentResources == nil {
		currentResources = &xds.Resources{}
	}
	newResources := subtractResources(currentResources, &resources)

	// For now we only care about listeners, to match the existing (pre ADS) implementation of xds server.
	var callbackTypeURLs map[string]func(error)
	if len(currentResources.Listeners) != len(newResources.Listeners) {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: nil}
	}
	changes := computeChanges(currentResources, &newResources)

	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	if callback != nil {
		if callbackTypeURLs == nil {
			callbackTypeURLs = map[string]func(error){}
		}
		callbackTypeURLs[ListenerTypeURL] = callback
	}
	return s.updateSnapshot(ctx, &newResources, "", waitGroup, callbackTypeURLs, changes)
}

// mergeResources copies all resources from src into dst (upsert semantics).
func mergeResources(dst *xds.Resources, src *xds.Resources) {
	if src == nil {
		return
	}
	maps.Copy(dst.Listeners, src.Listeners)
	maps.Copy(dst.Routes, src.Routes)
	maps.Copy(dst.Clusters, src.Clusters)
	maps.Copy(dst.Endpoints, src.Endpoints)
	maps.Copy(dst.Secrets, src.Secrets)
	maps.Copy(dst.NetworkPolicies, src.NetworkPolicies)
	maps.Copy(dst.NetworkPolicyHosts, src.NetworkPolicyHosts)
}

// Subtracts all resources present in b from a.
func subtractResources(a *xds.Resources, b *xds.Resources) xds.Resources {
	diffResources := xds.Resources{
		Listeners:          make(map[string]*envoy_config_listener.Listener),
		Clusters:           make(map[string]*envoy_config_cluster.Cluster),
		Routes:             make(map[string]*envoy_config_route.RouteConfiguration),
		Endpoints:          make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:            make(map[string]*envoy_config_tls.Secret),
		NetworkPolicies:    make(map[string]*cilium.NetworkPolicy),
		NetworkPolicyHosts: make(map[string]*cilium.NetworkPolicyHosts),
	}
	if a == nil || b == nil {
		return diffResources
	}

	for name, ep := range a.Endpoints {
		if _, present := b.Endpoints[name]; !present {
			diffResources.Endpoints[name] = ep
		}
	}

	for name, cluster := range a.Clusters {
		if _, present := b.Clusters[name]; !present {
			diffResources.Clusters[name] = cluster
		}
	}

	for name, route := range a.Routes {
		if _, present := b.Routes[name]; !present {
			diffResources.Routes[name] = route
		}
	}

	for name, listener := range a.Listeners {
		if _, present := b.Listeners[name]; !present {
			diffResources.Listeners[name] = listener
		}
	}

	for name, secret := range a.Secrets {
		if _, present := b.Secrets[name]; !present {
			diffResources.Secrets[name] = secret
		}
	}

	for name, nwPolicy := range a.NetworkPolicies {
		if _, present := b.NetworkPolicies[name]; !present {
			diffResources.NetworkPolicies[name] = nwPolicy
		}
	}
	for name, nwPolicyHosts := range a.NetworkPolicyHosts {
		if _, present := b.NetworkPolicyHosts[name]; !present {
			diffResources.NetworkPolicyHosts[name] = nwPolicyHosts
		}
	}

	return diffResources
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

func getUpdatedTypeURLs(changes *resourceChanges) map[string]func(error) {
	if changes == nil {
		return nil
	}
	var updatedTypeURLS map[string]func(error)
	add := func(typeURL string) {
		if updatedTypeURLS == nil {
			updatedTypeURLS = make(map[string]func(error))
		}
		updatedTypeURLS[typeURL] = nil
	}
	if len(changes.listeners) > 0 {
		add(ListenerTypeURL)
	}
	if len(changes.routes) > 0 {
		add(RouteTypeURL)
	}
	if len(changes.clusters) > 0 {
		add(ClusterTypeURL)
	}
	if len(changes.endpoints) > 0 {
		add(EndpointTypeURL)
	}
	if len(changes.secrets) > 0 {
		add(SecretTypeURL)
	}
	if len(changes.networkPolicies) > 0 {
		add(NetworkPolicyTypeURL)
	}
	if len(changes.networkPolicyHosts) > 0 {
		add(NetworkPolicyHostsTypeURL)
	}
	return updatedTypeURLS
}
