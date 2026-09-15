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

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	xds_cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"google.golang.org/protobuf/proto"
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

	// resourceGenerationTracker records the generation which last changed each
	// resource name. Rollbacks use it to leave newer resources untouched.
	resourceGenerationTracker *resourceGenerationTracker

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
		resourceGenerationTracker: &resourceGenerationTracker{
			nodes:  make(map[string]*resourceGenerationState),
			owners: make(map[string]map[rollbackOwnerKey]uint32),
		},
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

	resources := s.cache.GetAllResources(localNodeID)

	if resources == nil {
		s.logger.Info(fmt.Sprintf("Failed to get existing resources for node %s, creating new one", localNodeID))
		resources = &xds.Resources{
			Listeners: make(map[string]*envoy_config_listener.Listener),
		}
	} else {
		resources = resources.CloneListeners()
	}
	oldListener, existed := resources.Listeners[name]
	resources.Listeners[name] = listenerConfig
	var callbackTypeURLs map[string]func(error)
	if wg != nil {
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: cb}
	}
	if err := s.updateSnapshot(ctx, resources, localNodeID, wg, callbackTypeURLs,
		&resourceChanges{listeners: []savedEntry[*envoy_config_listener.Listener]{{key: name, value: oldListener, existed: existed}}}); err != nil {
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
	resources = resources.CloneListeners()
	delete(resources.Listeners, name)

	var changes *resourceChanges
	var callbackTypeURLs map[string]func(error)
	if wg != nil {
		changes = &resourceChanges{listeners: []savedEntry[*envoy_config_listener.Listener]{{key: name, value: oldListener, existed: existed}}}
		callbackTypeURLs = map[string]func(error){ListenerTypeURL: nil}
	}
	s.updateSnapshot(ctx, resources, localNodeID, wg, callbackTypeURLs, changes)
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
					updatedResources := resources.CloneNetworkPolicies()
					delete(updatedResources.NetworkPolicies, dupName)
					s.updateSnapshot(ctx, updatedResources, localNodeID, nil, nil, nil)
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
	waitForACK := wg != nil && s.restorerPromise == nil && !s.npdsListeners.Empty()
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

	updatedNodeIDs := make([]string, 0, len(nodeIDs))
	for _, nodeId := range nodeIDs {
		resources := s.cache.GetAllResources(nodeId)
		if resources == nil {
			resources = &xds.Resources{}
		}
		oldPolicy, existed := resources.NetworkPolicies[resourceName]
		if existed && (oldPolicy == networkPolicy || proto.Equal(oldPolicy, networkPolicy)) {
			if waitForACK {
				generation, ok := s.resourceGenerationTracker.networkPolicyGeneration(nodeId, resourceName)
				if !ok {
					generation = s.resourceGenerations[nodeId]
				}
				if err := s.cache.AwaitCurrentVersion(nodeId, generation, wg, map[string]func(error){NetworkPolicyTypeURL: callback}); err != nil {
					return err, nil, nil
				}
			}
			continue
		}

		// Preserve the immutable published generation by copying the Resources
		// header and only the resource map changed by this update.
		updatedResources := resources.CloneNetworkPolicies()
		updatedResources.NetworkPolicies[resourceName] = networkPolicy
		var callbackTypeURLs map[string]func(error)
		if waitForACK {
			callbackTypeURLs = map[string]func(error){NetworkPolicyTypeURL: callback}
		}
		if err := s.updateSnapshot(ctx, updatedResources, nodeId, wg, callbackTypeURLs,
			&resourceChanges{networkPolicies: []savedEntry[*cilium.NetworkPolicy]{{key: resourceName, value: oldPolicy, existed: existed}}}); err != nil {
			return err, nil, nil
		}
		updatedNodeIDs = append(updatedNodeIDs, nodeId)
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

			// Remove each policy this call added and re-push its snapshot. Nodes
			// whose policy was already current require no xDS revert.
			for _, nodeId := range updatedNodeIDs {
				resources := s.cache.GetAllResources(nodeId)
				if resources == nil {
					continue
				}
				updatedResources := resources.CloneNetworkPolicies()
				oldPolicy, existed := updatedResources.NetworkPolicies[resourceName]
				delete(updatedResources.NetworkPolicies, resourceName)
				changes := &resourceChanges{
					networkPolicies: []savedEntry[*cilium.NetworkPolicy]{{
						key:     resourceName,
						value:   oldPolicy,
						existed: existed,
					}},
				}
				if err := s.updateSnapshot(ctx, updatedResources, nodeId, nil, nil, changes); err != nil {
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
	updatedResources := resources.CloneNetworkPolicies()
	oldPolicy, existed := updatedResources.NetworkPolicies[resourceName]
	delete(updatedResources.NetworkPolicies, resourceName)

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
	s.updateSnapshot(ctx, updatedResources, localNodeID, nil, nil, changes)
}

func (s *adsServer) RemoveAllNetworkPolicies() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	resources := s.cache.GetAllResources(localNodeID)
	if resources == nil {
		return
	}
	newResources := *resources
	newResources.NetworkPolicies = map[string]*cilium.NetworkPolicy{}

	if err := s.updateSnapshot(context.Background(), &newResources, localNodeID, nil, nil, computeChanges(resources, &newResources)); err != nil {
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

type resourceGenerationEntry struct {
	generation uint64
	exists     bool
}

type resourceGenerationState struct {
	listeners          map[string]resourceGenerationEntry
	routes             map[string]resourceGenerationEntry
	clusters           map[string]resourceGenerationEntry
	endpoints          map[string]resourceGenerationEntry
	secrets            map[string]resourceGenerationEntry
	networkPolicies    map[string]resourceGenerationEntry
	networkPolicyHosts map[string]resourceGenerationEntry
}

type rollbackOwnerKey struct {
	typeURL    string
	name       string
	generation uint64
}

// resourceGenerationTracker records per-resource generations independently of
// the ADS server mutex because completion finalizers run from xDS callbacks.
type resourceGenerationTracker struct {
	mutex  lock.Mutex
	nodes  map[string]*resourceGenerationState
	owners map[string]map[rollbackOwnerKey]uint32
}

func recordResourceGenerations[V any](generations *map[string]resourceGenerationEntry, resources map[string]V, changes []savedEntry[V], generation uint64) {
	if len(changes) == 0 {
		return
	}
	if *generations == nil {
		*generations = make(map[string]resourceGenerationEntry, len(changes))
	}
	for i := range changes {
		change := &changes[i]
		entry, existed := (*generations)[change.key]
		change.previousGeneration = entry
		change.previousGenerationExisted = existed
		_, exists := resources[change.key]
		(*generations)[change.key] = resourceGenerationEntry{generation: generation, exists: exists}
	}
}

func restoreResourceGenerations[V any](generations *map[string]resourceGenerationEntry, changes []savedEntry[V]) {
	for _, change := range changes {
		if change.previousGenerationExisted {
			if *generations == nil {
				*generations = make(map[string]resourceGenerationEntry)
			}
			(*generations)[change.key] = change.previousGeneration
		} else {
			delete(*generations, change.key)
		}
	}
	if len(*generations) == 0 {
		*generations = nil
	}
}

func resourceGenerationStateEmpty(state *resourceGenerationState) bool {
	return state == nil ||
		len(state.listeners) == 0 && len(state.routes) == 0 &&
			len(state.clusters) == 0 && len(state.endpoints) == 0 &&
			len(state.secrets) == 0 && len(state.networkPolicies) == 0 &&
			len(state.networkPolicyHosts) == 0
}

func (tracker *resourceGenerationTracker) record(nodeID string, generation uint64, resources *xds.Resources, changes *resourceChanges) {
	if resourceChangesEmpty(changes) {
		return
	}
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	state := tracker.nodes[nodeID]
	if state == nil {
		state = &resourceGenerationState{}
		tracker.nodes[nodeID] = state
	}
	if resources == nil {
		resources = &xds.Resources{}
	}
	recordResourceGenerations(&state.listeners, resources.Listeners, changes.listeners, generation)
	recordResourceGenerations(&state.routes, resources.Routes, changes.routes, generation)
	recordResourceGenerations(&state.clusters, resources.Clusters, changes.clusters, generation)
	recordResourceGenerations(&state.endpoints, resources.Endpoints, changes.endpoints, generation)
	recordResourceGenerations(&state.secrets, resources.Secrets, changes.secrets, generation)
	recordResourceGenerations(&state.networkPolicies, resources.NetworkPolicies, changes.networkPolicies, generation)
	recordResourceGenerations(&state.networkPolicyHosts, resources.NetworkPolicyHosts, changes.networkPolicyHosts, generation)
}

func (tracker *resourceGenerationTracker) restore(nodeID string, changes *resourceChanges) {
	if resourceChangesEmpty(changes) {
		return
	}
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	state := tracker.nodes[nodeID]
	if state == nil {
		state = &resourceGenerationState{}
		tracker.nodes[nodeID] = state
	}
	restoreResourceGenerations(&state.listeners, changes.listeners)
	restoreResourceGenerations(&state.routes, changes.routes)
	restoreResourceGenerations(&state.clusters, changes.clusters)
	restoreResourceGenerations(&state.endpoints, changes.endpoints)
	restoreResourceGenerations(&state.secrets, changes.secrets)
	restoreResourceGenerations(&state.networkPolicies, changes.networkPolicies)
	restoreResourceGenerations(&state.networkPolicyHosts, changes.networkPolicyHosts)
	if resourceGenerationStateEmpty(state) {
		delete(tracker.nodes, nodeID)
	}
}

func (tracker *resourceGenerationTracker) networkPolicyGeneration(nodeID, name string) (uint64, bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	state := tracker.nodes[nodeID]
	if state == nil {
		return 0, false
	}
	entry, ok := state.networkPolicies[name]
	return entry.generation, ok
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

// computeChangesForTypeURLs captures only directly changed resource types.
// Snapshot generation may additionally dirty dependent types, but those types
// do not own resource mutations and therefore need no rollback state.
func computeChangesForTypeURLs(current, new *xds.Resources, typeURLs map[string]struct{}) *resourceChanges {
	if current == nil {
		current = &xds.Resources{}
	}
	if new == nil {
		new = &xds.Resources{}
	}
	changes := &resourceChanges{}
	if _, changed := typeURLs[ListenerTypeURL]; changed {
		changes.listeners = diffMap(current.Listeners, new.Listeners)
	}
	if _, changed := typeURLs[RouteTypeURL]; changed {
		changes.routes = diffMap(current.Routes, new.Routes)
	}
	if _, changed := typeURLs[ClusterTypeURL]; changed {
		changes.clusters = diffMap(current.Clusters, new.Clusters)
	}
	if _, changed := typeURLs[EndpointTypeURL]; changed {
		changes.endpoints = diffMap(current.Endpoints, new.Endpoints)
	}
	if _, changed := typeURLs[SecretTypeURL]; changed {
		changes.secrets = diffMap(current.Secrets, new.Secrets)
	}
	if _, changed := typeURLs[NetworkPolicyTypeURL]; changed {
		changes.networkPolicies = diffMap(current.NetworkPolicies, new.NetworkPolicies)
	}
	if _, changed := typeURLs[NetworkPolicyHostsTypeURL]; changed {
		changes.networkPolicyHosts = diffMap(current.NetworkPolicyHosts, new.NetworkPolicyHosts)
	}
	return changes
}

func inferredCompletionTypeURLs(changes *resourceChanges) map[string]func(error) {
	// In ADS, CDS/RDS/EDS/SDS ACKs can be delayed by dependencies that are
	// reconciled by later StateDB rows. A generic wait for every changed type can
	// therefore block those rows from being published. Only infer the LDS wait
	// needed by listener add/remove callers; callers that need other ACKs pass
	// explicit callback type URLs.
	if changes == nil || len(changes.listeners) == 0 {
		return nil
	}
	return map[string]func(error){ListenerTypeURL: nil}
}

func listenerPortAllocationCompletionTypeURLs(callback func(error), changes *resourceChanges) map[string]func(error) {
	if callback == nil {
		return nil
	}

	callbackTypeURLs := map[string]func(error){ListenerTypeURL: callback}
	if changes != nil && len(changes.clusters) > 0 {
		// The legacy split xDS server waits for CDS ACKs before publishing the
		// listener update. Keep the same safety for ADS listener updates that also
		// change clusters; otherwise a listener ACK can unblock CEC reconciliation
		// while Envoy still lacks a cluster referenced by the listener filter chain.
		// Do not add RDS/EDS/SDS here, as those ACKs can legitimately be delayed by
		// resources reconciled through later StateDB rows.
		callbackTypeURLs[ClusterTypeURL] = nil
	}
	return callbackTypeURLs
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

// pruneUnreferencedRoutes removes RDS resources that become temporarily
// unreferenced while listeners are staged for deletion. Strict ADS snapshots
// reject unreferenced routes, so the routes are restored with the replacement
// listeners in the final snapshot.
func pruneUnreferencedRoutes(resources *xds.Resources) {
	referenced := make(map[string]struct{})
	for _, listener := range resources.Listeners {
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

	for name := range resources.Routes {
		if _, found := referenced[name]; !found {
			delete(resources.Routes, name)
		}
	}
}

func changesForTypeURL(changes *resourceChanges, typeURL string) *resourceChanges {
	selected := &resourceChanges{}
	if changes == nil {
		return selected
	}

	switch typeURL {
	case ListenerTypeURL:
		selected.listeners = changes.listeners
	case RouteTypeURL:
		selected.routes = changes.routes
	case ClusterTypeURL:
		selected.clusters = changes.clusters
	case EndpointTypeURL:
		selected.endpoints = changes.endpoints
	case SecretTypeURL:
		selected.secrets = changes.secrets
	case NetworkPolicyTypeURL:
		selected.networkPolicies = changes.networkPolicies
	case NetworkPolicyHostsTypeURL:
		selected.networkPolicyHosts = changes.networkPolicyHosts
	}
	return selected
}

func setExpectedGeneration[V any](entries []savedEntry[V], generations map[string]resourceGenerationEntry, fallback uint64) {
	for i := range entries {
		entries[i].expectedGeneration = fallback
		if entry, ok := generations[entries[i].key]; ok {
			entries[i].expectedGeneration = entry.generation
		}
	}
}

func addRollbackOwners[V any](owners *map[rollbackOwnerKey]uint32, typeURL string, entries []savedEntry[V], generations map[string]resourceGenerationEntry) {
	for _, entry := range entries {
		current, ok := generations[entry.key]
		if !ok || current.exists || current.generation != entry.expectedGeneration {
			continue
		}
		if *owners == nil {
			*owners = make(map[rollbackOwnerKey]uint32)
		}
		(*owners)[rollbackOwnerKey{typeURL: typeURL, name: entry.key, generation: entry.expectedGeneration}]++
	}
}

func releaseRollbackOwners[V any](owners map[rollbackOwnerKey]uint32, typeURL string, entries []savedEntry[V], generations map[string]resourceGenerationEntry) {
	for _, entry := range entries {
		key := rollbackOwnerKey{typeURL: typeURL, name: entry.key, generation: entry.expectedGeneration}
		count := owners[key]
		if count <= 1 {
			delete(owners, key)
			current, ok := generations[entry.key]
			if ok && !current.exists && current.generation == entry.expectedGeneration {
				delete(generations, entry.key)
			}
		} else {
			owners[key] = count - 1
		}
	}
}

func filterResourceChanges[V any](entries []savedEntry[V], generations map[string]resourceGenerationEntry, chainedGeneration uint64) []savedEntry[V] {
	var filtered []savedEntry[V]
	for _, entry := range entries {
		current, ok := generations[entry.key]
		if !ok {
			continue
		}
		if current.generation == entry.expectedGeneration || current.generation == chainedGeneration {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func resourceChangesEmpty(changes *resourceChanges) bool {
	return changes == nil ||
		len(changes.listeners) == 0 && len(changes.routes) == 0 &&
			len(changes.clusters) == 0 && len(changes.endpoints) == 0 &&
			len(changes.secrets) == 0 && len(changes.networkPolicies) == 0 &&
			len(changes.networkPolicyHosts) == 0
}

func (tracker *resourceGenerationTracker) prepareRollbackLocked(nodeID string, changes *resourceChanges, fallbackGeneration uint64) {
	state := tracker.nodes[nodeID]
	if state == nil {
		state = &resourceGenerationState{}
		tracker.nodes[nodeID] = state
	}
	setExpectedGeneration(changes.listeners, state.listeners, fallbackGeneration)
	setExpectedGeneration(changes.routes, state.routes, fallbackGeneration)
	setExpectedGeneration(changes.clusters, state.clusters, fallbackGeneration)
	setExpectedGeneration(changes.endpoints, state.endpoints, fallbackGeneration)
	setExpectedGeneration(changes.secrets, state.secrets, fallbackGeneration)
	setExpectedGeneration(changes.networkPolicies, state.networkPolicies, fallbackGeneration)
	setExpectedGeneration(changes.networkPolicyHosts, state.networkPolicyHosts, fallbackGeneration)

	owners := tracker.owners[nodeID]
	addRollbackOwners(&owners, ListenerTypeURL, changes.listeners, state.listeners)
	addRollbackOwners(&owners, RouteTypeURL, changes.routes, state.routes)
	addRollbackOwners(&owners, ClusterTypeURL, changes.clusters, state.clusters)
	addRollbackOwners(&owners, EndpointTypeURL, changes.endpoints, state.endpoints)
	addRollbackOwners(&owners, SecretTypeURL, changes.secrets, state.secrets)
	addRollbackOwners(&owners, NetworkPolicyTypeURL, changes.networkPolicies, state.networkPolicies)
	addRollbackOwners(&owners, NetworkPolicyHostsTypeURL, changes.networkPolicyHosts, state.networkPolicyHosts)
	if len(owners) > 0 {
		tracker.owners[nodeID] = owners
	}
}

func (tracker *resourceGenerationTracker) filterRollbackLocked(nodeID string, changes *resourceChanges, chainedGeneration uint64) *resourceChanges {
	state := tracker.nodes[nodeID]
	if state == nil {
		return &resourceChanges{}
	}
	return &resourceChanges{
		listeners:          filterResourceChanges(changes.listeners, state.listeners, chainedGeneration),
		routes:             filterResourceChanges(changes.routes, state.routes, chainedGeneration),
		clusters:           filterResourceChanges(changes.clusters, state.clusters, chainedGeneration),
		endpoints:          filterResourceChanges(changes.endpoints, state.endpoints, chainedGeneration),
		secrets:            filterResourceChanges(changes.secrets, state.secrets, chainedGeneration),
		networkPolicies:    filterResourceChanges(changes.networkPolicies, state.networkPolicies, chainedGeneration),
		networkPolicyHosts: filterResourceChanges(changes.networkPolicyHosts, state.networkPolicyHosts, chainedGeneration),
	}
}

func (tracker *resourceGenerationTracker) releaseRollbackLocked(nodeID string, changes *resourceChanges) {
	state := tracker.nodes[nodeID]
	if state == nil {
		return
	}
	owners := tracker.owners[nodeID]
	releaseRollbackOwners(owners, ListenerTypeURL, changes.listeners, state.listeners)
	releaseRollbackOwners(owners, RouteTypeURL, changes.routes, state.routes)
	releaseRollbackOwners(owners, ClusterTypeURL, changes.clusters, state.clusters)
	releaseRollbackOwners(owners, EndpointTypeURL, changes.endpoints, state.endpoints)
	releaseRollbackOwners(owners, SecretTypeURL, changes.secrets, state.secrets)
	releaseRollbackOwners(owners, NetworkPolicyTypeURL, changes.networkPolicies, state.networkPolicies)
	releaseRollbackOwners(owners, NetworkPolicyHostsTypeURL, changes.networkPolicyHosts, state.networkPolicyHosts)
	if len(owners) == 0 {
		delete(tracker.owners, nodeID)
	}
	if resourceGenerationStateEmpty(state) {
		delete(tracker.nodes, nodeID)
	}
}

func pruneUnownedTombstones(generations map[string]resourceGenerationEntry, owners map[rollbackOwnerKey]uint32, typeURL string, throughGeneration uint64) {
	for name, current := range generations {
		if current.exists || current.generation > throughGeneration ||
			owners[rollbackOwnerKey{typeURL: typeURL, name: name, generation: current.generation}] != 0 {
			continue
		}
		delete(generations, name)
	}
}

// pruneUnownedTombstonesLocked drops generation metadata for removals whose
// finalized state needs no rollback (for example, add-then-remove coalescing).
// Tombstones referenced by an older response stay live until that response is
// ACKed or NACKed.
func (tracker *resourceGenerationTracker) pruneUnownedTombstonesLocked(nodeID, typeURL string, throughGeneration uint64) {
	state := tracker.nodes[nodeID]
	if state == nil {
		return
	}
	owners := tracker.owners[nodeID]
	switch typeURL {
	case ListenerTypeURL:
		pruneUnownedTombstones(state.listeners, owners, typeURL, throughGeneration)
	case RouteTypeURL:
		pruneUnownedTombstones(state.routes, owners, typeURL, throughGeneration)
	case ClusterTypeURL:
		pruneUnownedTombstones(state.clusters, owners, typeURL, throughGeneration)
	case EndpointTypeURL:
		pruneUnownedTombstones(state.endpoints, owners, typeURL, throughGeneration)
	case SecretTypeURL:
		pruneUnownedTombstones(state.secrets, owners, typeURL, throughGeneration)
	case NetworkPolicyTypeURL:
		pruneUnownedTombstones(state.networkPolicies, owners, typeURL, throughGeneration)
	case NetworkPolicyHostsTypeURL:
		pruneUnownedTombstones(state.networkPolicyHosts, owners, typeURL, throughGeneration)
	}
	if len(owners) == 0 {
		delete(tracker.owners, nodeID)
	}
	if resourceGenerationStateEmpty(state) {
		delete(tracker.nodes, nodeID)
	}
}

type resourceRollbackLifecycle struct {
	server           *adsServer
	ctx              context.Context
	nodeID           string
	pushedGeneration uint64
	changes          *resourceChanges
	done             bool
}

func (lifecycle *resourceRollbackLifecycle) warnDuplicateLocked(operation string) {
	lifecycle.server.logger.Warn("Ignoring duplicate resource rollback terminal operation",
		logfields.NodeID, lifecycle.nodeID,
		logfields.XDSGeneration, lifecycle.pushedGeneration,
		logfields.Operation, operation)
}

func (lifecycle *resourceRollbackLifecycle) Finalize() {
	tracker := lifecycle.server.resourceGenerationTracker
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	if lifecycle.done {
		lifecycle.warnDuplicateLocked("finalize")
		return
	}
	lifecycle.done = true
	tracker.releaseRollbackLocked(lifecycle.nodeID, lifecycle.changes)
	lifecycle.changes = nil
}

func (lifecycle *resourceRollbackLifecycle) Revert(expectedGeneration uint64) (uint64, bool) {
	s := lifecycle.server
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tracker := s.resourceGenerationTracker
	tracker.mutex.Lock()
	if lifecycle.done {
		lifecycle.warnDuplicateLocked("revert")
		tracker.mutex.Unlock()
		return expectedGeneration, false
	}
	lifecycle.done = true
	changes := tracker.filterRollbackLocked(lifecycle.nodeID, lifecycle.changes, expectedGeneration)
	tracker.releaseRollbackLocked(lifecycle.nodeID, lifecycle.changes)
	lifecycle.changes = nil
	tracker.mutex.Unlock()

	currentGeneration := s.resourceGenerations[lifecycle.nodeID]
	if resourceChangesEmpty(changes) {
		s.logger.Debug("Skipping revert, affected resources have been superseded",
			logfields.NodeID, lifecycle.nodeID,
			logfields.XDSPushedGeneration, lifecycle.pushedGeneration,
			logfields.XDSExpectedGeneration, expectedGeneration,
			logfields.XDSCurrentGeneration, currentGeneration)
		// Preserve the rollback chain token. Returning the node's newer current
		// generation here could let an older coalesced rollback overwrite the
		// resource which caused this rollback to be skipped.
		return expectedGeneration, false
	}

	currentResources := s.cache.GetAllResources(lifecycle.nodeID)
	s.logger.Info("Reverting resources for node", logfields.NodeID, lifecycle.nodeID)
	reverted := applyChanges(currentResources, changes)
	revertChanges := computeChanges(currentResources, reverted)
	if err := s.updateSnapshot(lifecycle.ctx, reverted, lifecycle.nodeID, nil, nil, revertChanges); err != nil {
		s.logger.Error("Failed to revert snapshot",
			logfields.NodeID, lifecycle.nodeID,
			logfields.Error, err)
		return expectedGeneration, false
	}
	return s.resourceGenerations[lifecycle.nodeID], true
}

// buildRevert captures the changes for one resource type and returns a closure
// that restores them. The caller threads the actual generation returned by one
// successful revert into the next older revert. A revert is skipped if the
// current generation no longer matches that rollback chain.
// Caller must hold s.mutex.
func (s *adsServer) buildRevert(ctx context.Context, nodeID, typeURL string, pushedGeneration uint64, changes *resourceChanges) xdsnew.Rollback {
	changes = changesForTypeURL(changes, typeURL)
	tracker := s.resourceGenerationTracker
	tracker.mutex.Lock()
	tracker.prepareRollbackLocked(nodeID, changes, pushedGeneration)
	tracker.pruneUnownedTombstonesLocked(nodeID, typeURL, pushedGeneration)
	tracker.mutex.Unlock()
	lifecycle := &resourceRollbackLifecycle{
		server:           s,
		ctx:              ctx,
		nodeID:           nodeID,
		pushedGeneration: pushedGeneration,
		changes:          changes,
	}
	return lifecycle
}

// savedEntry records the previous value of a single resource key.
// If existed is false, the key was not present before the update and should be deleted on revert.
type savedEntry[V any] struct {
	key                       string
	value                     V
	existed                   bool
	expectedGeneration        uint64
	previousGeneration        resourceGenerationEntry
	previousGenerationExisted bool
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

func cloneMapOrInit[K comparable, V any](source map[K]V) map[K]V {
	cloned := maps.Clone(source)
	if cloned == nil {
		cloned = make(map[K]V)
	}
	return cloned
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

func applyChanges(r *xds.Resources, changes *resourceChanges) *xds.Resources {
	// Clone only maps that the revert is about to mutate. Published resource
	// maps are immutable, so all unaffected maps can be shared.
	updated := *r
	if len(changes.listeners) > 0 {
		updated.Listeners = cloneMapOrInit(r.Listeners)
		applyDiff(updated.Listeners, changes.listeners)
	}
	if len(changes.routes) > 0 {
		updated.Routes = cloneMapOrInit(r.Routes)
		applyDiff(updated.Routes, changes.routes)
	}
	if len(changes.clusters) > 0 {
		updated.Clusters = cloneMapOrInit(r.Clusters)
		applyDiff(updated.Clusters, changes.clusters)
	}
	if len(changes.endpoints) > 0 {
		updated.Endpoints = cloneMapOrInit(r.Endpoints)
		applyDiff(updated.Endpoints, changes.endpoints)
	}
	if len(changes.secrets) > 0 {
		updated.Secrets = cloneMapOrInit(r.Secrets)
		applyDiff(updated.Secrets, changes.secrets)
	}
	if len(changes.networkPolicies) > 0 {
		updated.NetworkPolicies = cloneMapOrInit(r.NetworkPolicies)
		applyDiff(updated.NetworkPolicies, changes.networkPolicies)
	}
	if len(changes.networkPolicyHosts) > 0 {
		updated.NetworkPolicyHosts = cloneMapOrInit(r.NetworkPolicyHosts)
		applyDiff(updated.NetworkPolicyHosts, changes.networkPolicyHosts)
	}
	return &updated
}

// Caller must hold s.mutex.
func (s *adsServer) updateSnapshot(ctx context.Context, resources *xds.Resources, nodeId string, wg *completion.WaitGroup, callbackTypeURLs map[string]func(err error), changes *resourceChanges) error {
	return s.updateSnapshotWithRevert(ctx, resources, nodeId, wg, callbackTypeURLs, changes, true)
}

// Caller must hold s.mutex.
func (s *adsServer) updateSnapshotWithRevert(ctx context.Context, resources *xds.Resources, nodeId string, wg *completion.WaitGroup, callbackTypeURLs map[string]func(err error), changes *resourceChanges, revertOnNACK bool) error {
	if nodeId == "" {
		// Host proxy uses "127.0.0.1" as the nodeID
		nodeId = localNodeID
	}

	restoring := s.restorerPromise != nil
	callbacks := callbackTypeURLs
	if restoring {
		wg = nil
		// An explicitly empty set prevents inferred resource types from
		// registering waits while Envoy is intentionally unable to connect.
		callbackTypeURLs = map[string]func(error){}
	}

	s.logger.Debug("updateXdsSnapshot: Updating Envoy resources",
		logfields.Resource, resources.DebugInfo())
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
	// Preserve the semantic resource changes before callback-only type URLs are
	// merged below. ACK bookkeeping must not cause unrelated snapshot groups to
	// be regenerated.
	var changedTypeURLs map[string]struct{}
	if updatedTypeURLsInSnapshot != nil {
		changedTypeURLs = make(map[string]struct{}, len(updatedTypeURLsInSnapshot))
		for typeURL := range updatedTypeURLsInSnapshot {
			changedTypeURLs[typeURL] = struct{}{}
		}
	}
	completionTypeURLs := inferredCompletionTypeURLs(changes)
	// Callers can explicitly add type URLs when the changed type cannot be
	// inferred from the changed resource entries. When explicit callback types
	// are provided, use them as the completion set too: callers such as CEC port
	// allocation only need the listener ACK/NACK, and waiting for all changed ADS
	// types can deadlock behind dependent resources reconciled by later StateDB
	// rows.
	if callbackTypeURLs != nil {
		if updatedTypeURLsInSnapshot == nil {
			updatedTypeURLsInSnapshot = make(map[string]func(error), len(callbackTypeURLs))
		}
		for typeURL := range callbackTypeURLs {
			if _, ok := updatedTypeURLsInSnapshot[typeURL]; !ok {
				updatedTypeURLsInSnapshot[typeURL] = nil
			}
		}
		completionTypeURLs = callbackTypeURLs
	}
	if changes == nil || len(updatedTypeURLsInSnapshot) > 0 || s.cache.GetAllResources(nodeId) == nil {
		// Reserve the next generation before registering the revert closure. It
		// becomes current after the immutable resources have been staged. The
		// actual snapshot may be finalized later when Envoy opens its next watch.
		newGeneration := s.resourceGeneration + 1
		var revertFactory xdsnew.RevertFactory
		// A resource mutation without an ACK-tracked completion can still be
		// coalesced into a later response. Preserve response-owned rollback state
		// beyond the lifetime of the caller so a delayed NACK can restore every
		// resource change represented by that response.
		if revertOnNACK && changes != nil && len(changedTypeURLs) > 0 {
			revertFactory = func(generation uint64, previous, current *xds.Resources, changedTypeURLs map[string]struct{}) xdsnew.Rollback {
				for typeURL := range changedTypeURLs {
					return s.buildRevert(context.Background(), nodeId, typeURL, generation,
						computeChangesForTypeURLs(previous, current, changedTypeURLs))
				}
				return nil
			}
		}
		generator := func(resources *xds.Resources, previous xds_cache.ResourceSnapshot, changedTypeURLs map[string]struct{}) (xds_cache.ResourceSnapshot, error) {
			snapshot, err := s.cache.GenerateSnapshotIncrementally(resources, previous, changedTypeURLs, s.logger)
			if err != nil {
				return nil, err
			}
			if s.config.envoyXDSMode.IsStrictADS() {
				if err := xdsnew.CheckSnapshotConsistency(snapshot); err != nil {
					return nil, fmt.Errorf("generated ADS snapshot is inconsistent: %w", err)
				}
			}
			return snapshot, nil
		}
		// Record the generation before UpdateResources can synchronously finalize
		// an open watch and build its response rollback.
		s.resourceGenerationTracker.record(nodeId, newGeneration, resources, changes)
		err := s.cache.UpdateResources(ctx, nodeId, newGeneration, resources, changedTypeURLs, generator, wg, completionTypeURLs, nil, revertFactory)
		if err != nil {
			s.resourceGenerationTracker.restore(nodeId, changes)
			s.logger.Error("Error staging snapshot resources",
				logfields.NodeID, nodeId,
				logfields.Error, err)
			return err
		}
		s.resourceGeneration = newGeneration
		s.resourceGenerations[nodeId] = newGeneration
	} else {
		s.logger.Debug("updateXdsSnapshot: Resources are identical, skipping update")
	}

	if nodeId == localNodeID {
		s.syncNPDSListeners(resources)
	}
	if restoring {
		for _, callback := range callbacks {
			if callback != nil {
				callback(nil)
			}
		}
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
	// Merge new resources into a copy-on-write view of current resources.
	// Only resource-type maps that contain upserts are cloned.
	merged := updateResources(currentResources, nil, &resources)
	changes := computeChanges(currentResources, &merged)

	callback := s.portAllocationCallback(ctx, resources.PortAllocationCallbacks)
	callbackTypeURLs := listenerPortAllocationCompletionTypeURLs(callback, changes)
	return s.updateSnapshot(ctx, &merged, "", wg, callbackTypeURLs, changes)
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

	currentResources := s.cache.GetAllResources(localNodeID)
	if currentResources == nil {
		currentResources = &xds.Resources{}
	}
	// Subtract old resources and merge new resources using copy-on-write.
	// A resource-type map touched by both operations is still cloned only once.
	updated := updateResources(currentResources, &oldResources, &newResources)
	changes := computeChanges(currentResources, &updated)

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
		callbackTypeURLs = listenerPortAllocationCompletionTypeURLs(callback, changes)
	}
	if len(listenersToRecreate) == 0 || s.restorerPromise != nil {
		return s.updateSnapshot(ctx, &updated, "", waitGroup, callbackTypeURLs, changes)
	}

	// Envoy cannot replace a listener's address set in place when SO_REUSEPORT
	// is disabled, because the replacement overlaps sockets still owned by the
	// active listener. Publish and ACK a snapshot without the listener first so
	// Envoy closes those sockets before the replacement is sent.
	staged := currentResources.CloneListeners()
	for _, name := range listenersToRecreate {
		delete(staged.Listeners, name)
	}
	if s.config.envoyXDSMode.IsStrictADS() {
		// pruneUnreferencedRoutes mutates Routes. Keep the published map
		// immutable while sharing every resource map left untouched by staging.
		staged.Routes = cloneMapOrInit(currentResources.Routes)
		pruneUnreferencedRoutes(staged)
	}
	// The listener-address transaction handles failures synchronously while
	// holding s.mutex. Still pass the actual changes to generation tracking so
	// an older delayed rollback cannot overwrite one of these transaction phases.
	updateWithoutRevert := func(ctx context.Context, resources *xds.Resources, wg *completion.WaitGroup, callbackTypeURLs map[string]func(error)) error {
		published := s.cache.GetAllResources(localNodeID)
		if published == nil {
			published = &xds.Resources{}
		}
		changes := computeChanges(published, resources)
		return s.updateSnapshotWithRevert(ctx, resources, "", wg, callbackTypeURLs, changes, false)
	}

	restore := func(cause error) error {
		restoreErr := updateWithoutRevert(context.WithoutCancel(ctx), currentResources, nil, nil)
		if restoreErr != nil {
			return fmt.Errorf("%w; failed to restore ADS snapshot: %w", cause, restoreErr)
		}
		return cause
	}

	s.logger.Debug("UpdateEnvoyResources: deleting listeners before address change",
		logfields.ResourcesDeleted, len(listenersToRecreate))
	// Both transaction phases are awaited while s.mutex is held. Disable the
	// asynchronous NACK revert, which would try to reacquire the same mutex;
	// restore handles failures synchronously below instead.
	deleteWG := completion.NewWaitGroup(ctx)
	if err := updateWithoutRevert(ctx, staged, deleteWG, map[string]func(error){ListenerTypeURL: nil}); err != nil {
		return err
	}
	if err := deleteWG.Wait(); err != nil {
		return restore(fmt.Errorf("waiting for listener deletion ACK: %w", err))
	}

	// Always wait for the replacement LDS ACK, even when the caller did not
	// supply a wait group. This keeps the two snapshots transactional and lets us
	// restore the last working listener if Envoy rejects the replacement.
	if callbackTypeURLs == nil {
		callbackTypeURLs = make(map[string]func(error))
	}
	if _, found := callbackTypeURLs[ListenerTypeURL]; !found {
		callbackTypeURLs[ListenerTypeURL] = nil
	}
	// Envoy can ACK the deletion before every worker has released its listening
	// sockets. Re-stage the accepted deletion snapshot and retry only that
	// transient bind failure; all other NACKs restore the original snapshot.
	for attempt := 1; ; attempt++ {
		replaceWG := completion.NewWaitGroup(ctx)
		err := updateWithoutRevert(ctx, &updated, replaceWG, callbackTypeURLs)
		if err == nil {
			err = replaceWG.Wait()
		}
		if err == nil {
			return nil
		}

		if !isAddressAlreadyInUseError(err) || attempt >= listenerAddressChangeMaxAttempts {
			return restore(fmt.Errorf("waiting for replacement listener ACK: %w", err))
		}

		// The rejected desired snapshot remains in the cache. Publish the already
		// ACKed deletion snapshot again so the same desired version can be sent as
		// a fresh response on the next attempt.
		if stageErr := updateWithoutRevert(ctx, staged, nil, nil); stageErr != nil {
			return restore(fmt.Errorf("re-staging listener deletion after bind failure: %w", stageErr))
		}

		s.logger.Debug("UpdateEnvoyResources: Retrying ADS listener address change after bind failure",
			logfields.Attempt, attempt+1,
			logfields.Error, err)
		timer := time.NewTimer(listenerAddressChangeRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return restore(ctx.Err())
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

	currentResources := s.cache.GetAllResources(localNodeID)
	if currentResources == nil {
		currentResources = &xds.Resources{}
	}
	newResources := updateResources(currentResources, &resources, nil)

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

// updateResourceMap returns current unchanged when neither operation touches the
// resource type. Otherwise it clones the map once, applies removals, then upserts.
func updateResourceMap[V any](current, removed, upserted map[string]V) map[string]V {
	if len(removed) == 0 && len(upserted) == 0 {
		return current
	}

	updated := cloneMapOrInit(current)
	for name := range removed {
		delete(updated, name)
	}
	maps.Copy(updated, upserted)
	return updated
}

// updateResources applies removals and upserts using copy-on-write per resource
// type. Unaffected maps remain shared with the immutable current resources.
func updateResources(current, removed, upserted *xds.Resources) xds.Resources {
	var updated, removeSet, upsertSet xds.Resources
	if current != nil {
		updated = *current
	}
	if removed != nil {
		removeSet = *removed
	}
	if upserted != nil {
		upsertSet = *upserted
	}

	updated.Listeners = updateResourceMap(updated.Listeners, removeSet.Listeners, upsertSet.Listeners)
	updated.Routes = updateResourceMap(updated.Routes, removeSet.Routes, upsertSet.Routes)
	updated.Clusters = updateResourceMap(updated.Clusters, removeSet.Clusters, upsertSet.Clusters)
	updated.Endpoints = updateResourceMap(updated.Endpoints, removeSet.Endpoints, upsertSet.Endpoints)
	updated.Secrets = updateResourceMap(updated.Secrets, removeSet.Secrets, upsertSet.Secrets)
	updated.NetworkPolicies = updateResourceMap(updated.NetworkPolicies, removeSet.NetworkPolicies, upsertSet.NetworkPolicies)
	updated.NetworkPolicyHosts = updateResourceMap(updated.NetworkPolicyHosts, removeSet.NetworkPolicyHosts, upsertSet.NetworkPolicyHosts)
	return updated
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
	updatedTypeURLS := make(map[string]func(error))
	add := func(typeURL string) {
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
