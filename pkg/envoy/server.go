// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envoy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/api/kafka"
	"github.com/cilium/cilium/pkg/proxy/logger"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_bootstrap "github.com/cilium/proxy/go/envoy/config/bootstrap/v3"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_mongo_proxy "github.com/cilium/proxy/go/envoy/extensions/filters/network/mongo_proxy/v3"
	envoy_mysql_proxy "github.com/cilium/proxy/go/envoy/extensions/filters/network/mysql_proxy/v3"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_upstream "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
	"golang.org/x/sys/unix"
)

var (
	// allowAllPortNetworkPolicy is a PortNetworkPolicy that allows all traffic
	// to any L4 port.
	allowAllPortNetworkPolicy = []*cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		{Protocol: envoy_config_core.SocketAddress_TCP},
		// Allow all UDP traffic to any port.
		// UDP rules not sent to Envoy for now.
		// {Protocol: envoy_config_core.SocketAddress_UDP},
	}
)

const (
	adminClusterName      = "envoy-admin"
	egressClusterName     = "egress-cluster"
	egressTLSClusterName  = "egress-cluster-tls"
	ingressClusterName    = "ingress-cluster"
	ingressTLSClusterName = "ingress-cluster-tls"
	metricsListenerName   = "envoy-prometheus-metrics-listener"
	EnvoyTimeout          = 300 * time.Second // must be smaller than endpoint.EndpointGenerationTimeout
)

type Listener struct {
	// must hold the XDSServer.mutex when accessing 'count'
	count uint

	// mutex is needed when accessing the fields below.
	// XDSServer.mutex is not needed, but if taken it must be taken before 'mutex'
	mutex   lock.RWMutex
	acked   bool
	nacked  bool
	waiters []*completion.Completion
}

// XDSServer provides a high-lever interface to manage resources published
// using the xDS gRPC API.
type XDSServer struct {
	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// accessLogPath is the path to the L7 access logs
	accessLogPath string

	// mutex protects accesses to the configuration resources below.
	mutex lock.RWMutex

	// listenerMutator publishes listener updates to Envoy proxies.
	// Manages it's own locking
	listenerMutator xds.AckingResourceMutator

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

	// networkPolicyEndpoints maps each network policy's name to the info on
	// the local endpoint.
	// mutex must be held when accessing this.
	networkPolicyEndpoints map[string]logger.EndpointUpdater

	// stopServer stops the xDS gRPC server.
	stopServer context.CancelFunc
}

func getXDSPath(stateDir string) string {
	return filepath.Join(stateDir, "xds.sock")
}

func toAny(pb proto.Message) *any.Any {
	a, err := ptypes.MarshalAny(pb)
	if err != nil {
		panic(err.Error())
	}
	return a
}

// StartXDSServer configures and starts the xDS GRPC server.
func StartXDSServer(stateDir string) *XDSServer {
	xdsPath := getXDSPath(stateDir)

	os.Remove(xdsPath)
	socketListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: xdsPath, Net: "unix"})
	if err != nil {
		log.WithError(err).Fatalf("Envoy: Failed to open xDS listen socket at %s", xdsPath)
	}

	// Make the socket accessible by non-root Envoy proxies, e.g. running in
	// sidecar containers.
	if err = os.Chmod(xdsPath, 0777); err != nil {
		log.WithError(err).Fatalf("Envoy: Failed to change mode of xDS listen socket at %s", xdsPath)
	}

	ldsCache := xds.NewCache()
	ldsMutator := xds.NewAckingResourceMutatorWrapper(ldsCache)
	ldsConfig := &xds.ResourceTypeConfiguration{
		Source:      ldsCache,
		AckObserver: ldsMutator,
	}

	npdsCache := xds.NewCache()
	npdsMutator := xds.NewAckingResourceMutatorWrapper(npdsCache)
	npdsConfig := &xds.ResourceTypeConfiguration{
		Source:      npdsCache,
		AckObserver: npdsMutator,
	}

	nphdsConfig := &xds.ResourceTypeConfiguration{
		Source:      NetworkPolicyHostsCache,
		AckObserver: &NetworkPolicyHostsCache,
	}

	stopServer := startXDSGRPCServer(socketListener, ldsConfig, npdsConfig, nphdsConfig, 5*time.Second)

	return &XDSServer{
		socketPath:             xdsPath,
		accessLogPath:          getAccessLogPath(stateDir),
		listenerMutator:        ldsMutator,
		listeners:              make(map[string]*Listener),
		networkPolicyCache:     npdsCache,
		NetworkPolicyMutator:   npdsMutator,
		networkPolicyEndpoints: make(map[string]logger.EndpointUpdater),
		stopServer:             stopServer,
	}
}

func (s *XDSServer) getHttpFilterChainProto(clusterName string, tls bool) *envoy_config_listener.FilterChain {
	denied403body := option.Config.HTTP403Message
	requestTimeout := int64(option.Config.HTTPRequestTimeout) // seconds
	idleTimeout := int64(option.Config.HTTPIdleTimeout)       // seconds
	maxGRPCTimeout := int64(option.Config.HTTPMaxGRPCTimeout) // seconds
	numRetries := uint32(option.Config.HTTPRetryCount)
	retryTimeout := int64(option.Config.HTTPRetryTimeout) //seconds

	hcmConfig := &envoy_config_http.HttpConnectionManager{
		StatPrefix: "proxy",
		HttpFilters: []*envoy_config_http.HttpFilter{{
			Name: "cilium.l7policy",
			ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
				TypedConfig: toAny(&cilium.L7Policy{
					AccessLogPath:  s.accessLogPath,
					Denied_403Body: denied403body,
				}),
			},
		}, {
			Name: "envoy.filters.http.router",
		}},
		StreamIdleTimeout: &duration.Duration{}, // 0 == disabled
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
								Timeout: &duration.Duration{Seconds: requestTimeout},
								MaxStreamDuration: &envoy_config_route.RouteAction_MaxStreamDuration{
									GrpcTimeoutHeaderMax: &duration.Duration{Seconds: maxGRPCTimeout},
								},
								RetryPolicy: &envoy_config_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrappers.UInt32Value{Value: numRetries},
									PerTryTimeout: &duration.Duration{Seconds: retryTimeout},
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
								Timeout: &duration.Duration{Seconds: requestTimeout},
								//IdleTimeout: &duration.Duration{Seconds: idleTimeout},
								RetryPolicy: &envoy_config_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrappers.UInt32Value{Value: numRetries},
									PerTryTimeout: &duration.Duration{Seconds: retryTimeout},
								},
							},
						},
					}},
				}},
			},
		},
	}

	if option.Config.HTTPNormalizePath {
		hcmConfig.NormalizePath = &wrappers.BoolValue{Value: true}
		hcmConfig.MergeSlashes = true
		hcmConfig.PathWithEscapedSlashesAction = envoy_config_http.HttpConnectionManager_UNESCAPE_AND_REDIRECT
	}

	// Idle timeout can only be specified if non-zero
	if idleTimeout > 0 {
		hcmConfig.GetRouteConfig().VirtualHosts[0].Routes[1].GetRoute().IdleTimeout = &duration.Duration{Seconds: idleTimeout}
	}

	chain := &envoy_config_listener.FilterChain{
		Filters: []*envoy_config_listener.Filter{{
			Name: "cilium.network",
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
func (s *XDSServer) getTcpFilterChainProto(clusterName string, filterName string, config *any.Any) *envoy_config_listener.FilterChain {
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
		FilterChainMatch: &envoy_config_listener.FilterChainMatch{
			// must have transport match, otherwise TLS inspector will be automatically inserted
			TransportProtocol: "raw_buffer",
		},
	}

	if filterName != "" {
		// Add filter chain match for 'filterName' so that connections for which policy says to use this L7
		// are handled by this filter chain.
		chain.FilterChainMatch.ApplicationProtocols = []string{filterName}
	}

	return chain
}

// AddMetricsListener adds a prometheus metrics listener to Envoy.
// We could do this in the bootstrap config, but then a failure to bind to the configured port
// would fail starting Envoy.
func (s *XDSServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	if port == 0 {
		return // 0 == disabled
	}

	log.WithField(logfields.Port, port).Debug("Envoy: AddMetricsListener")

	s.addListener(metricsListenerName, port, func() *envoy_config_listener.Listener {
		hcmConfig := &envoy_config_http.HttpConnectionManager{
			StatPrefix: metricsListenerName,
			HttpFilters: []*envoy_config_http.HttpFilter{{
				Name: "envoy.filters.http.router",
			}},
			StreamIdleTimeout: &duration.Duration{}, // 0 == disabled
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
			Name: metricsListenerName,
			Address: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "::",
						Ipv4Compat:    true,
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
					},
				},
			},
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
func (s *XDSServer) addListener(name string, port uint16, listenerConf func() *envoy_config_listener.Listener, wg *completion.WaitGroup, cb func(err error), isProxyListener bool) {
	s.mutex.Lock()
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
		if !listener.acked {
			// Listener not acked yet, add a completion to the waiter's list
			log.Debugf("Envoy: Waiting for a non-acknowledged reused listener: %s", name)
			listener.waiters = append(listener.waiters, wg.AddCompletion())
		}
		listener.mutex.Unlock()
		s.mutex.Unlock()
		return
	}
	// Try again after a NACK, potentially with a different port number, etc.
	if listener.nacked {
		listener.acked = false
		listener.nacked = false
	}
	listener.mutex.Unlock() // Listener locked again in callbacks below

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf(), []string{"127.0.0.1"}, wg,
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
				waiter.Complete(err)
			}
			listener.waiters = nil
			listener.mutex.Unlock()

			if cb != nil {
				cb(err)
			}
		})
	s.mutex.Unlock()
}

func (s *XDSServer) getListenerConf(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool) *envoy_config_listener.Listener {
	clusterName := egressClusterName
	socketMark := int64(0xB00)
	if isIngress {
		clusterName = ingressClusterName
		socketMark = 0xA00
	}

	listenerConf := &envoy_config_listener.Listener{
		Name: name,
		Address: &envoy_config_core.Address{
			Address: &envoy_config_core.Address_SocketAddress{
				SocketAddress: &envoy_config_core.SocketAddress{
					Protocol:      envoy_config_core.SocketAddress_TCP,
					Address:       "::",
					Ipv4Compat:    true,
					PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
				},
			},
		},
		Transparent: &wrappers.BoolValue{Value: true},
		SocketOptions: []*envoy_config_core.SocketOption{{
			Description: "Listener socket mark",
			Level:       unix.SOL_SOCKET,
			Name:        unix.SO_MARK,
			Value:       &envoy_config_core.SocketOption_IntValue{IntValue: socketMark},
			State:       envoy_config_core.SocketOption_STATE_PREBIND,
		}},
		// FilterChains: []*envoy_config_listener.FilterChain
		ListenerFilters: []*envoy_config_listener.ListenerFilter{{
			Name: "cilium.bpf_metadata",
			ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
				TypedConfig: toAny(&cilium.BpfMetadata{
					IsIngress:                   isIngress,
					MayUseOriginalSourceAddress: mayUseOriginalSourceAddr,
					BpfRoot:                     bpf.GetMapRoot(),
				}),
			},
		}},
	}

	// Add filter chains
	if kind == policy.ParserTypeHTTP {
		// Use tls_inspector only with HTTP, insert as the first filter
		listenerConf.ListenerFilters = append([]*envoy_config_listener.ListenerFilter{{
			Name: "envoy.filters.listener.tls_inspector",
		}}, listenerConf.ListenerFilters...)

		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(clusterName, false))

		// Add a TLS variant
		tlsClusterName := egressTLSClusterName
		if isIngress {
			tlsClusterName = ingressTLSClusterName
		}
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(tlsClusterName, true))
	} else {
		// Default TCP chain, takes care of all parsers in proxylib
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName, "", nil))

		// Experimental TCP chain for MySQL 5.x
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName,
			"envoy.filters.network.mysql_proxy", toAny(&envoy_mysql_proxy.MySQLProxy{
				StatPrefix: "mysql",
			})))

		// Experimental TCP chain for MongoDB
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName,
			"envoy.filters.network.mongo_proxy", toAny(&envoy_mongo_proxy.MongoProxy{
				StatPrefix:          "mongo",
				EmitDynamicMetadata: true,
			})))
	}
	return listenerConf
}

// AddListener adds a listener to a running Envoy proxy.
func (s *XDSServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) {
	log.Debugf("Envoy: %s AddListener %s (mayUseOriginalSourceAddr: %v)", kind, name, mayUseOriginalSourceAddr)

	s.addListener(name, port, func() *envoy_config_listener.Listener {
		return s.getListenerConf(name, kind, port, isIngress, mayUseOriginalSourceAddr)
	}, wg, nil, true)
}

// RemoveListener removes an existing Envoy Listener.
func (s *XDSServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	return s.removeListener(name, wg, true)
}

// removeListener removes an existing Envoy Listener.
func (s *XDSServer) removeListener(name string, wg *completion.WaitGroup, isProxyListener bool) xds.AckingResourceMutatorRevertFunc {
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

func (s *XDSServer) stop() {
	s.stopServer()
	os.Remove(s.socketPath)
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
							}}
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
							}}
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

func getSecretString(certManager policy.CertificateManager, hdr *api.HeaderMatch, ns string) (string, error) {
	value := ""
	var err error
	if hdr.Secret != nil {
		if certManager == nil {
			err = fmt.Errorf("HeaderMatches: Nil certManager")
		} else {
			value, err = certManager.GetSecretString(context.TODO(), hdr.Secret, ns)
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

func getHTTPRule(certManager policy.CertificateManager, h *api.PortRuleHTTP, ns string) (*cilium.HttpNetworkPolicyRule, bool) {
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

	googleRe2 := &envoy_type_matcher.RegexMatcher_GoogleRe2{GoogleRe2: &envoy_type_matcher.RegexMatcher_GoogleRE2{}}

	headers := make([]*envoy_config_route.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":path",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
					EngineType: googleRe2,
					Regex:      h.Path,
				}}})
	}
	if h.Method != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":method",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
					EngineType: googleRe2,
					Regex:      h.Method,
				}}})
	}
	if h.Host != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":authority",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
					EngineType: googleRe2,
					Regex:      h.Host,
				}}})
	}
	for _, hdr := range h.Headers {
		strs := strings.SplitN(hdr, " ", 2)
		if len(strs) == 2 {
			// Remove ':' in "X-Key: true"
			key := strings.TrimRight(strs[0], ":")
			// Header presence and matching (literal) value needed.
			headers = append(headers, &envoy_config_route.HeaderMatcher{Name: key,
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_ExactMatch{ExactMatch: strs[1]}})
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_config_route.HeaderMatcher{Name: strs[0],
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true}})
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
		value, err := getSecretString(certManager, hdr, ns)
		if err != nil {
			log.WithError(err).Warning("Failed fetching K8s Secret, header match will fail")
			// Envoy treats an empty exact match value as matching ANY value; adding
			// InvertMatch: true here will cause this rule to NEVER match.
			headers = append(headers, &envoy_config_route.HeaderMatcher{Name: hdr.Name,
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_ExactMatch{ExactMatch: ""},
				InvertMatch:          true})
		} else {
			// Header presence and matching (literal) value needed.
			if mismatch_action == cilium.HeaderMatch_FAIL_ON_MISMATCH {
				if value != "" {
					headers = append(headers, &envoy_config_route.HeaderMatcher{Name: hdr.Name,
						HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_ExactMatch{ExactMatch: value}})
				} else {
					// Only header presence needed
					headers = append(headers, &envoy_config_route.HeaderMatcher{Name: hdr.Name,
						HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true}})
				}
			} else {
				log.Debugf("HeaderMatches: Adding %s: %s", hdr.Name, value)
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

func createBootstrap(filePath string, nodeId, cluster string, xdsSock, egressClusterName, ingressClusterName string, adminPath string) {
	connectTimeout := int64(option.Config.ProxyConnectTimeout) // in seconds

	useDownstreamProtocol := map[string]*any.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamProtocolConfig{
				UseDownstreamProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamHttpConfig{},
			},
		}),
	}

	http2ProtocolOptions := map[string]*any.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_config_upstream.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
				},
			},
		}),
	}

	bs := &envoy_config_bootstrap.Bootstrap{
		Node: &envoy_config_core.Node{Id: nodeId, Cluster: cluster},
		StaticResources: &envoy_config_bootstrap.Bootstrap_StaticResources{
			Clusters: []*envoy_config_cluster.Cluster{
				{
					Name:                          egressClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:               &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocol,
				},
				{
					Name:                          egressTLSClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:               &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocol,
					TransportSocket:               &envoy_config_core.TransportSocket{Name: "cilium.tls_wrapper"},
				},
				{
					Name:                          ingressClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:               &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocol,
				},
				{
					Name:                          ingressTLSClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:               &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocol,
					TransportSocket:               &envoy_config_core.TransportSocket{Name: "cilium.tls_wrapper"},
				},
				{
					Name:                 "xds-grpc-cilium",
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_STATIC},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					LbPolicy:             envoy_config_cluster.Cluster_ROUND_ROBIN,
					LoadAssignment: &envoy_config_endpoint.ClusterLoadAssignment{
						ClusterName: "xds-grpc-cilium",
						Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
							LbEndpoints: []*envoy_config_endpoint.LbEndpoint{{
								HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
									Endpoint: &envoy_config_endpoint.Endpoint{
										Address: &envoy_config_core.Address{
											Address: &envoy_config_core.Address_Pipe{
												Pipe: &envoy_config_core.Pipe{Path: xdsSock}},
										},
									},
								},
							}},
						}},
					},
					TypedExtensionProtocolOptions: http2ProtocolOptions,
				},
				{
					Name:                 adminClusterName,
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_STATIC},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					LbPolicy:             envoy_config_cluster.Cluster_ROUND_ROBIN,
					LoadAssignment: &envoy_config_endpoint.ClusterLoadAssignment{
						ClusterName: adminClusterName,
						Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
							LbEndpoints: []*envoy_config_endpoint.LbEndpoint{{
								HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
									Endpoint: &envoy_config_endpoint.Endpoint{
										Address: &envoy_config_core.Address{
											Address: &envoy_config_core.Address_Pipe{
												Pipe: &envoy_config_core.Pipe{Path: adminPath}},
										},
									},
								},
							}},
						}},
					},
				},
			},
		},
		DynamicResources: &envoy_config_bootstrap.Bootstrap_DynamicResources{
			LdsConfig: &envoy_config_core.ConfigSource{
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
										ClusterName: "xds-grpc-cilium",
									},
								},
							},
						},
					},
				},
			},
		},
		Admin: &envoy_config_bootstrap.Admin{
			Address: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_Pipe{
					Pipe: &envoy_config_core.Pipe{Path: adminPath},
				},
			},
		},
		LayeredRuntime: &envoy_config_bootstrap.LayeredRuntime{
			Layers: []*envoy_config_bootstrap.RuntimeLayer{
				{
					Name: "static_layer_0",
					LayerSpecifier: &envoy_config_bootstrap.RuntimeLayer_StaticLayer{
						StaticLayer: &structpb.Struct{Fields: map[string]*structpb.Value{
							"overload": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"global_downstream_max_connections": {Kind: &structpb.Value_NumberValue{NumberValue: 50000}},
							}}}},
						}},
					},
				},
			},
		},
	}

	log.Debugf("Envoy: Bootstrap: %s", bs)
	data, err := proto.Marshal(bs)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error marshaling Envoy bootstrap")
	}
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error writing Envoy bootstrap file")
	}
}

func getCiliumTLSContext(tls *policy.TLSContext) *cilium.TLSContext {
	return &cilium.TLSContext{
		TrustedCa:        tls.TrustedCA,
		CertificateChain: tls.CertificateChain,
		PrivateKey:       tls.PrivateKey,
	}
}

func GetEnvoyHTTPRules(certManager policy.CertificateManager, l7Rules *api.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool) {
	if len(l7Rules.HTTP) > 0 { // Just cautious. This should never be false.
		// Assume none of the rules have side-effects so that rule evaluation can
		// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
		// is set to 'false' below if any rules with side effects are encountered,
		// causing all the applicable rules to be evaluated instead.
		canShortCircuit := true
		httpRules := make([]*cilium.HttpNetworkPolicyRule, 0, len(l7Rules.HTTP))
		for _, l7 := range l7Rules.HTTP {
			var cs bool
			rule, cs := getHTTPRule(certManager, &l7, ns)
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

func getPortNetworkPolicyRule(sel policy.CachedSelector, wildcard bool, l7Parser policy.L7ParserType, l7Rules *policy.PerSelectorPolicy) (*cilium.PortNetworkPolicyRule, bool) {
	r := &cilium.PortNetworkPolicyRule{}

	// Optimize the policy if the endpoint selector is a wildcard by
	// keeping remote policies list empty to match all remote policies.
	if !wildcard {
		for _, id := range sel.GetSelections() {
			r.RemotePolicies = append(r.RemotePolicies, uint64(id))
		}

		// No remote policies would match this rule. Discard it.
		if len(r.RemotePolicies) == 0 {
			return nil, true
		}
	}

	if l7Rules == nil {
		// L3/L4 only rule, everything in L7 is allowed && no TLS
		return r, true
	}

	if l7Rules.TerminatingTLS != nil {
		r.DownstreamTlsContext = getCiliumTLSContext(l7Rules.TerminatingTLS)
	}
	if l7Rules.OriginatingTLS != nil {
		r.UpstreamTlsContext = getCiliumTLSContext(l7Rules.OriginatingTLS)
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
			// convert from []uint32 to []uint64
			remotePolicies := make([]uint64, len(selections))
			for i, id := range selections {
				remotePolicies[i] = uint64(id)
			}
			return &cilium.PortNetworkPolicyRule{
				RemotePolicies: remotePolicies,
			}
		}
	}

	// Use map to remove duplicates
	remoteMap := make(map[uint64]struct{})
	wildcardFound := false
	for sel, l7 := range selectors {
		if sel.IsWildcard() {
			wildcardFound = true
			break
		}

		for _, id := range sel.GetSelections() {
			remoteMap[uint64(id)] = struct{}{}
		}

		if !l7.IsEmpty() {
			// If it is not empty then we issue the warning.
			// Deny rules don't support L7 therefore for the deny case
			// l7.IsEmpty() will always return true.
			log.Warningf("L3-only rule for selector %v surprisingly has L7 rules (%v)!", sel, *l7)
		}
	}

	if wildcardFound {
		// Optimize the policy if the endpoint selector is a wildcard by
		// keeping remote policies list empty to match all remote policies.
		remoteMap = nil
	} else if len(remoteMap) == 0 {
		// No remote policies would match this rule. Discard it.
		return nil
	}

	// Convert to a sorted slice
	remotePolicies := make([]uint64, 0, len(remoteMap))
	for id := range remoteMap {
		remotePolicies = append(remotePolicies, id)
	}
	sort.Slice(remotePolicies, func(i, j int) bool {
		return remotePolicies[i] < remotePolicies[j]
	})

	return &cilium.PortNetworkPolicyRule{
		RemotePolicies: remotePolicies,
	}
}

func getDirectionNetworkPolicy(ep logger.EndpointUpdater, l4Policy policy.L4PolicyMap, policyEnforced bool) []*cilium.PortNetworkPolicy {
	if !policyEnforced {
		// Return an allow-all policy.
		return allowAllPortNetworkPolicy
	}

	if len(l4Policy) == 0 {
		return nil
	}

	PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, len(l4Policy))
	for _, l4 := range l4Policy {
		var protocol envoy_config_core.SocketAddress_Protocol
		switch l4.Protocol {
		case api.ProtoTCP:
			protocol = envoy_config_core.SocketAddress_TCP
		case api.ProtoUDP:
			// UDP rules not sent to Envoy for now.
			continue
		}

		port := uint16(l4.Port)
		if port == 0 && l4.PortName != "" {
			port = ep.GetNamedPortLocked(l4.Ingress, l4.PortName, uint8(l4.U8Proto))
			if port == 0 {
				continue
			}
		}

		rules := make([]*cilium.PortNetworkPolicyRule, 0, len(l4.L7RulesPerSelector))
		allowAll := false

		// Assume none of the rules have side-effects so that rule evaluation can
		// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
		// is set to 'false' below if any rules with side effects are encountered,
		// causing all the applicable rules to be evaluated instead.
		canShortCircuit := true

		if port == 0 {
			// L3-only rule, must generate L7 allow-all in case there are other
			// port-specific rules. Otherwise traffic from allowed remotes could be dropped.
			rule := getWildcardNetworkPolicyRule(l4.L7RulesPerSelector)
			if rule != nil {
				if len(rule.RemotePolicies) == 0 {
					// Got an allow-all rule, which can short-circuit all of
					// the other rules.
					allowAll = true
				}
				rules = append(rules, rule)
			}
		} else {
			nSelectors := len(l4.L7RulesPerSelector)
			for sel, l7 := range l4.L7RulesPerSelector {
				// A single selector is effectively a wildcard, as bpf passes through
				// only allowed l3. If there are multiple selectors for this l4-filter
				// then the proxy may need to drop some allowed l3 due to l7 rules potentially
				// being different between the selectors.
				wildcard := nSelectors == 1 || sel.IsWildcard()
				rule, cs := getPortNetworkPolicyRule(sel, wildcard, l4.L7Parser, l7)
				if rule != nil {
					if !cs {
						canShortCircuit = false
					}
					if len(rule.RemotePolicies) == 0 && rule.L7 == nil {
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
			continue
		}

		PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
			Port:     uint32(port),
			Protocol: protocol,
			Rules:    SortPortNetworkPolicyRules(rules),
		})
	}

	if len(PerPortPolicies) == 0 {
		return nil
	}

	return SortPortNetworkPolicies(PerPortPolicies)
}

// getNetworkPolicy converts a network policy into a cilium.NetworkPolicy.
func getNetworkPolicy(ep logger.EndpointUpdater, name string, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		Name:             name,
		Policy:           uint64(ep.GetIdentityLocked()),
		ConntrackMapName: ep.ConntrackNameLocked(),
	}

	// If no policy, deny all traffic. Otherwise, convert the policies for ingress and egress.
	if policy != nil {
		p.IngressPerPortPolicies = getDirectionNetworkPolicy(ep, policy.Ingress, ingressPolicyEnforced)
		p.EgressPerPortPolicies = getDirectionNetworkPolicy(ep, policy.Egress, egressPolicyEnforced)
	}

	return p
}

// return the Envoy proxy node IDs that need to ACK the policy.
func getNodeIDs(ep logger.EndpointUpdater, policy *policy.L4Policy) []string {
	nodeIDs := make([]string, 0, 1)
	if ep.HasSidecarProxy() {
		// Istio sidecars have the Cilium bpf metadata filter
		// statically configured running the NPDS client, so
		// we may unconditionally wait for ACKs from the
		// sidecars.
		// Sidecar's IPv4 address is used as the node ID.
		ipv4 := ep.GetIPv4Address()
		if ipv4 == "" {
			log.Error("Envoy: Sidecar proxy has no IPv4 address")
		} else {
			nodeIDs = append(nodeIDs, ipv4)
		}
	} else {
		// Host proxy uses "127.0.0.1" as the nodeID
		nodeIDs = append(nodeIDs, "127.0.0.1")
	}
	// Require additional ACK from proxylib if policy has proxylib redirects
	// Note that if a previous policy had a proxylib redirect and this one does not,
	// we only wait for the ACK from the main Envoy node ID.
	if policy.HasProxylibRedirect() {
		// Proxylib uses "127.0.0.2" as the nodeID
		nodeIDs = append(nodeIDs, "127.0.0.2")
	}
	return nodeIDs
}

// UpdateNetworkPolicy adds or updates a network policy in the set published
// to L7 proxies.
// When the proxy acknowledges the network policy update, it will result in
// a subsequent call to the endpoint's OnProxyPolicyUpdate() function.
func (s *XDSServer) UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// First, validate all policies
	ips := []string{
		ep.GetIPv6Address(),
		ep.GetIPv4Address(),
	}
	policies := make([]*cilium.NetworkPolicy, 0, len(ips))
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		networkPolicy := getNetworkPolicy(ep, ip, policy, ingressPolicyEnforced, egressPolicyEnforced)
		err := networkPolicy.Validate()
		if err != nil {
			return fmt.Errorf("error validating generated NetworkPolicy for %s: %s", ip, err), nil
		}
		policies = append(policies, networkPolicy)
	}

	nodeIDs := getNodeIDs(ep, policy)

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if !ep.HasSidecarProxy() {
		if s.proxyListeners == 0 {
			wg = nil
		}
	}

	// When successful, push them into the cache.
	revertFuncs := make([]xds.AckingResourceMutatorRevertFunc, 0, len(policies))
	revertUpdatedNetworkPolicyEndpoints := make(map[string]logger.EndpointUpdater, len(policies))
	for _, p := range policies {
		var callback func(error)
		if policy != nil {
			policyRevision := policy.Revision
			callback = func(err error) {
				if err == nil {
					go ep.OnProxyPolicyUpdate(policyRevision)
				}
			}
		}
		revertFuncs = append(revertFuncs, s.NetworkPolicyMutator.Upsert(NetworkPolicyTypeURL, p.Name, p, nodeIDs, wg, callback))
		revertUpdatedNetworkPolicyEndpoints[p.Name] = s.networkPolicyEndpoints[p.Name]
		s.networkPolicyEndpoints[p.Name] = ep
	}

	return nil, func() error {
		log.Debug("Reverting xDS network policy update")

		s.mutex.Lock()
		defer s.mutex.Unlock()

		for name, ep := range revertUpdatedNetworkPolicyEndpoints {
			if ep == nil {
				delete(s.networkPolicyEndpoints, name)
			} else {
				s.networkPolicyEndpoints[name] = ep
			}
		}

		// Don't wait for an ACK for the reverted xDS updates.
		// This is best-effort.
		for _, revertFunc := range revertFuncs {
			revertFunc(completion.NewCompletion(nil, nil))
		}

		log.Debug("Finished reverting xDS network policy update")

		return nil
	}
}

// UseCurrentNetworkPolicy inserts a Completion to the WaitGroup if the current network policy has not yet been acked.
// 'wg' may not be nil.
func (s *XDSServer) UseCurrentNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if !ep.HasSidecarProxy() && s.proxyListeners == 0 {
		return
	}

	nodeIDs := getNodeIDs(ep, policy)
	s.NetworkPolicyMutator.UseCurrent(NetworkPolicyTypeURL, nodeIDs, wg)
}

// RemoveNetworkPolicy removes network policies relevant to the specified
// endpoint from the set published to L7 proxies, and stops listening for
// acks for policies on this endpoint.
func (s *XDSServer) RemoveNetworkPolicy(ep logger.EndpointInfoSource) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	name := ep.GetIPv6Address()
	if name != "" {
		s.networkPolicyCache.Delete(NetworkPolicyTypeURL, name)
		delete(s.networkPolicyEndpoints, name)
	}
	name = ep.GetIPv4Address()
	if name != "" {
		s.networkPolicyCache.Delete(NetworkPolicyTypeURL, name)
		delete(s.networkPolicyEndpoints, name)
		// Delete node resources held in the cache for the endpoint (e.g., sidecar)
		s.NetworkPolicyMutator.DeleteNode(name)
	}
}

// RemoveAllNetworkPolicies removes all network policies from the set published
// to L7 proxies.
func (s *XDSServer) RemoveAllNetworkPolicies() {
	s.networkPolicyCache.Clear(NetworkPolicyTypeURL)
}

// GetNetworkPolicies returns the current version of the network policies with
// the given names.
// If resourceNames is empty, all resources are returned.
func (s *XDSServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	resources, err := s.networkPolicyCache.GetResources(context.Background(), NetworkPolicyTypeURL, 0, "", resourceNames)
	if err != nil {
		return nil, err
	}
	networkPolicies := make(map[string]*cilium.NetworkPolicy, len(resources.Resources))
	for _, res := range resources.Resources {
		networkPolicy := res.(*cilium.NetworkPolicy)
		networkPolicies[networkPolicy.Name] = networkPolicy
	}
	return networkPolicies, nil
}

// getLocalEndpoint returns the endpoint info for the local endpoint on which
// the network policy of the given name if enforced, or nil if not found.
func (s *XDSServer) getLocalEndpoint(networkPolicyName string) logger.EndpointUpdater {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.networkPolicyEndpoints[networkPolicyName]
}
