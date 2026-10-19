// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	cilium "github.com/cilium/proxy/go/cilium/api"
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

	// proxyListeners is the number of distinct redirect listeners.
	proxyListeners int

	// listenerCount is the set of names of listeners that have been added by
	// calling AddListener. Admin and metrics listeners do not own references.
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
	// prevents listener address updates from synchronously waiting for ACKs while
	// holding mutex before the ADS server starts serving. mutex must be held during
	// access after construction.
	restorerPromise promise.Promise[endpointstate.Restorer]
}

func newADSServerWithCache(cache xdsnew.Cache, logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) (*adsServer, error) {
	if !cache.HasNode(localNodeID) {
		return nil, fmt.Errorf("local ADS node %q is not initialized", localNodeID)
	}
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
	return adsServer, nil
}

// adsListenerObserver is owned by ADS but updated only under the cache lock.
// Neither method takes or assumes the adsServer mutex.
type adsListenerObserver struct {
	npdsListenerCount int
}

func (o *adsListenerObserver) ApplyCommittedChanges(nodeID string, changes []xdsnew.ListenerChange) bool {
	if nodeID != localNodeID {
		return false
	}
	before := o.npdsListenerCount
	for _, change := range changes {
		if listenerRequiresNPDS(change.Previous) {
			o.npdsListenerCount--
		}
		if listenerRequiresNPDS(change.Current) {
			o.npdsListenerCount++
		}
	}
	return before > 0 && o.npdsListenerCount == 0
}

func (o *adsListenerObserver) HasNPDSListeners(nodeID string) bool {
	// Untracked nodes retain their explicit ACK waits.
	return nodeID != localNodeID || o.npdsListenerCount > 0
}

func newADSCache(logger *slog.Logger) xdsnew.Cache {
	return xdsnew.NewCache(logger,
		xdsnew.WithNodeIDs(localNodeID),
		xdsnew.WithListenerObserver(&adsListenerObserver{}))
}

// newADSServer creates a new ADS GRPC server.
func newADSServer(logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) (*adsServer, error) {
	return newADSServerWithCache(newADSCache(logger), logger, ipCache, localEndpointStore, config, secretManager, restorerPromise)
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

	if err := s.addListener(ctx, s.getAdminListenerConfig(port), wg, false); err != nil {
		s.logger.Warn("Envoy: Adding admin listener failed",
			logfields.Port, port,
			logfields.Error, err,
		)
		return
	}
	s.logger.Info("Envoy: Configured Admin API listener", logfields.Port, port)
}

func (s *adsServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}
	s.logger.Debug(
		"Envoy: AddMetricsListener",
		logfields.Port, port,
	)
	if err := s.addListener(ctx, s.getMetricsListenerConfig(port), wg, false); err != nil {
		s.logger.Warn("Envoy: Adding metrics listener failed",
			logfields.Port, port,
			logfields.Error, err,
		)
		return
	}
	s.logger.Info("Envoy: Configured prometheus metrics listener", logfields.Port, port)
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

// addListener installs listener configuration. Redirect listeners retain
// references; admin and metrics listeners use response-owned NACK recovery.
func (s *adsServer) addListener(ctx context.Context, listenerConfig *envoy_config_listener.Listener, wg *completion.WaitGroup, isProxyListener bool) error {
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

	name := listenerConfig.GetName()
	if !isProxyListener {
		// Non-proxy listeners are applied with rollback so that an Envoy NACK will
		// automatically revert them.
		rollback, err := s.cache.ApplyResourceWithRollback(ctx, localNodeID, typeurl.Listener, name, listenerConfig, wg)
		if err != nil {
			return err
		}
		// There is no caller rollback decision for these listeners. Response-owned
		// recovery survives finalization, including when no WaitGroup was supplied.
		rollback.Finalize()
		return nil
	}

	// Proxy listeners are reference counted and added without automatic rollback, so that a
	// NACK for an another listener in the same Envoy response can not revert proxy listeners.
	count := s.listenerCount[name]
	if count == 0 {
		s.proxyListeners++
		s.logger.Info(
			"Envoy: Upserting new listener",
			logfields.Listener, name,
		)
	}
	count++
	s.listenerCount[name] = count

	return s.cache.ApplyResource(ctx, localNodeID, typeurl.Listener, name, listenerConfig, wg)
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

func (s *adsServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) error {
	s.logger.Debug(
		"Envoy: AddListener",
		logfields.L7ParserType, kind,
		logfields.Listener, name,
		logfields.MayUseOriginalSourceAddr, mayUseOriginalSourceAddr,
	)

	return s.addListener(ctx, s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr), wg, true)
}

// RemoveListener deletes the listener when its last redirect reference is released.
func (s *adsServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) {
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
	s.proxyListeners--
	delete(s.listenerCount, name)

	s.logger.Info(
		"Envoy: Deleting listener",
		logfields.Listener, name,
	)

	// Admitted removals are final, including when Envoy NACKs the response.
	_ = s.cache.ApplyResource(ctx, localNodeID, typeurl.Listener, name, nil, wg)
}

func (s *adsServer) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, epp *policy.EndpointPolicy,
	wg *completion.WaitGroup,
) (error, revert.Revertible) {
	if epp == nil {
		return ErrNilPolicy, nil
	}

	names := ep.GetPolicyNames()
	if len(names) == 0 {
		// It looks like the "host EP" (identity == 1) has no IPs, so it is possible to find
		// there are no policy names here. In this case just skip without updating a policy.
		s.logger.Debug("Endpoint has no policy names",
			logfields.Name, names,
			logfields.EndpointID, ep.GetID(),
		)
		return nil, nil
	}

	l4policy := &epp.SelectorPolicy.L4Policy
	ingressPolicyEnforced := epp.SelectorPolicy.IngressPolicyEnabled
	egressPolicyEnforced := epp.SelectorPolicy.EgressPolicyEnabled
	selectors := epp.GetPolicySelectors()

	// Error out if the selectors are no longer valid
	if !selectors.IsValid() {
		return policy.ErrStaleSelectors, nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Update local endpoint IP/policy mapping for access log correlation and log any conflicts.
	// This is done even if policy update fails, as this information only depends on the
	// existence of the endpoint and does not need to be reverted even if policy update fails.
	conflicts := s.localEndpointStore.setLocalEndpoint(ep, names)
	if len(conflicts) > 0 {
		s.logger.Error("Conflicting policy names detected while updating local endpoint store",
			logfields.EndpointID, ep.GetID(),
			logfields.Info, conflicts,
		)

		// Remove network policies for conflicting endpoints from the cache.
		for _, dup := range conflicts {
			dupName := strconv.FormatUint(dup.ep.GetID(), 10)
			_ = s.cache.ApplyResource(ctx, localNodeID, typeurl.NetworkPolicy, dupName, nil, nil)
		}
	}

	networkPolicy := s.getNetworkPolicy(ep, epp.SelectorPolicy.GetEgressNamedPorts, selectors, names, l4policy, ingressPolicyEnforced, egressPolicyEnforced, s.config.useFullTLSContext, s.config.useSDS, s.secretManager.GetSecretSyncNamespace())

	// First, validate the policy
	err := networkPolicy.Validate()
	if err != nil {
		return fmt.Errorf("error validating generated NetworkPolicy for %d/%s: %w", ep.GetID(), names, err), nil
	}

	epID := ep.GetID()
	resourceName := strconv.FormatUint(epID, 10)

	rollback, err := s.cache.ApplyResourceWithRollback(ctx, LocalNodeID, typeurl.NetworkPolicy, resourceName, networkPolicy, wg)
	if err != nil {
		return err, nil
	}
	// The cache lifecycle directly implements revert.Revertible. Passing it
	// through avoids allocating separate endpoint revert and finalize closures.
	return nil, rollback
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

	_ = s.cache.ApplyResource(ctx, localNodeID, typeurl.NetworkPolicy, resourceName, nil, nil)
}

func adsListenerReusePortDisabled(listener *envoy_config_listener.Listener) bool {
	reusePort := listener.GetEnableReusePort()
	return reusePort != nil && !reusePort.GetValue()
}

func (s *adsServer) UpsertSecret(ctx context.Context, secret *envoy_config_tls.Secret) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.cache.ApplyResource(ctx, localNodeID, typeurl.Secret, secret.GetName(), secret, nil)
}

func (s *adsServer) UpdateEnvoyResources(ctx context.Context, oldResources, newResources xds.Resources) (err error) {
	// Envoy can not have Listener ports updated while port reuse is disabled.
	// Collect listeners to be deleted first and recreated after, if any.
	var listenersToRecreate []string
	for name, oldListener := range oldResources.Listeners {
		newListener, found := newResources.Listeners[name]
		if !found {
			continue
		}

		if newListener != nil && !listenerAddressesEqual(oldListener, newListener) &&
			(adsListenerReusePortDisabled(oldListener) || adsListenerReusePortDisabled(newListener)) {
			listenersToRecreate = append(listenersToRecreate, name)
		}
	}

	// Wait for listeners and their supplied clusters, independently of port
	// allocation. Other named resource types may have no subscriber to ACK them.
	var waitTypeURLs typeurl.Set
	if len(newResources.Listeners) > 0 {
		waitTypeURLs.Insert(typeurl.Listener)
		if len(newResources.Clusters) > 0 {
			waitTypeURLs.Insert(typeurl.Cluster)
		}
	}

	s.mutex.Lock()

	// No waits if the agent is still restarting, as we are not serving xDS to Envoy yet.
	if s.restorerPromise != nil {
		mutations := xdsnew.ResourceMutations{Removed: oldResources, Upserted: newResources}
		rollback, err := s.cache.ApplyResourcesWithRollback(ctx, localNodeID, mutations, nil, waitTypeURLs)
		s.mutex.Unlock()
		if err == nil {
			rollback.Finalize()
		}
		return err
	}

	// Simple path when no listeners need to be recreated
	if len(listenersToRecreate) == 0 {
		var wg *completion.WaitGroup
		if !waitTypeURLs.Empty() {
			wg = completion.NewWaitGroup(ctx)
			defer wg.Cancel()
		}
		mutations := xdsnew.ResourceMutations{Removed: oldResources, Upserted: newResources}
		rollback, err := s.cache.ApplyResourcesWithRollback(ctx, localNodeID, mutations, wg, waitTypeURLs)
		// Ordinary waits must not block other server updates.
		s.mutex.Unlock()
		if err != nil {
			return err // Synchronous cache-update errors return immediately
		}
		if wg != nil {
			if err := wg.Wait(); err != nil {
				// Response recovery may already have reverted the NACKed type.
				// Undo the remaining changes atomically, without overwriting newer
				// cache values or resurrecting resources removed by later updates.
				return errors.Join(err, rollback.Revert())
			}
		}
		rollback.Finalize()
		return nil
	}

	// Serialize the exceptional delete/recreate sequence against other server
	// mutations, which must not interleave between its two listener versions.
	defer s.mutex.Unlock()

	// Envoy cannot replace a listener's address set in place when SO_REUSEPORT
	// is disabled, because the replacement overlaps sockets still owned by the
	// active listener. Publish and ACK a snapshot without the listener first so
	// Envoy closes those sockets before the replacement is sent.
	stagedMutations := xdsnew.ResourceMutations{
		Removed: xds.Resources{
			Listeners: make(map[string]*envoy_config_listener.Listener, len(listenersToRecreate)),
		},
	}
	for _, name := range listenersToRecreate {
		stagedMutations.Removed.Listeners[name] = oldResources.Listeners[name]
	}
	// ACK waits observe the caller's deadline, but cache mutations and recovery
	// must remain usable after that deadline.
	mutationCtx := context.WithoutCancel(ctx)
	s.logger.Debug("UpdateEnvoyResources: deleting listeners before address change",
		logfields.ResourcesDeleted, len(listenersToRecreate))
	deleteWG := completion.NewWaitGroup(ctx)
	defer deleteWG.Cancel()
	listenerWait := typeurl.NewSet(typeurl.Listener)
	deleteRollback, err := s.cache.ApplyResourcesWithRollback(mutationCtx, localNodeID, stagedMutations, deleteWG, listenerWait)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, deleteRollback.Revert())
		} else {
			deleteRollback.Finalize()
		}
	}()
	if err := deleteWG.Wait(); err != nil {
		return fmt.Errorf("waiting for listener deletion ACK: %w", err)
	}

	// Each attempt installs the replacement listeners. Failed attempts roll back
	// to the post-deletion state. On terminal failure, the deferred rollback also
	// undoes the initial listener deletions.
	replaceMutations := xdsnew.ResourceMutations{Removed: oldResources, Upserted: newResources}
	for attempt := 1; ; attempt++ {
		replaceWG := completion.NewWaitGroup(ctx)
		replaceRollback, err := s.cache.ApplyResourcesWithRollback(mutationCtx, localNodeID, replaceMutations, replaceWG, waitTypeURLs)
		if err == nil {
			err = replaceWG.Wait()
			if err == nil {
				replaceRollback.Finalize()
				return nil
			}
			// Cache-owned NACK recovery handles only the rejected resource type.
			// Undo the remaining changes from this attempt, including on timeout
			// or cancellation; transaction guards preserve superseding changes.
			err = errors.Join(err, replaceRollback.Revert())
		} else {
			replaceWG.Cancel()
		}

		if !isAddressAlreadyInUseError(err) || attempt >= listenerAddressChangeMaxAttempts {
			return fmt.Errorf("waiting for replacement listener ACK: %w", err)
		}

		// Give Envoy time to process the corrective LDS response and close
		// sockets before publishing another replacement.
		s.logger.Debug("UpdateEnvoyResources: Retrying ADS listener address change after bind failure",
			logfields.Attempt, attempt+1,
			logfields.Error, err)
		timer := time.NewTimer(listenerAddressChangeRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *adsServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources) error {
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

	return s.cache.ApplyResources(ctx, localNodeID, xdsnew.ResourceMutations{Removed: resources}, nil, typeurl.EmptySet)
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
