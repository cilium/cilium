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
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/logger"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_api_v2 "github.com/cilium/proxy/go/envoy/api/v2"
	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	envoy_api_v2_endpoint "github.com/cilium/proxy/go/envoy/api/v2/endpoint"
	envoy_api_v2_listener "github.com/cilium/proxy/go/envoy/api/v2/listener"
	envoy_api_v2_route "github.com/cilium/proxy/go/envoy/api/v2/route"
	envoy_config_bootstrap_v2 "github.com/cilium/proxy/go/envoy/config/bootstrap/v2"
	envoy_config_http "github.com/cilium/proxy/go/envoy/config/filter/network/http_connection_manager/v2"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/config/filter/network/tcp_proxy/v2"
	envoy_type_matcher "github.com/cilium/proxy/go/envoy/type/matcher"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
)

var (
	// allowAllPortNetworkPolicy is a PortNetworkPolicy that allows all traffic
	// to any L4 port.
	allowAllPortNetworkPolicy = []*cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		{Protocol: envoy_api_v2_core.SocketAddress_TCP},
		// Allow all UDP traffic to any port.
		{Protocol: envoy_api_v2_core.SocketAddress_UDP},
	}
)

const (
	egressClusterName     = "egress-cluster"
	egressTLSClusterName  = "egress-cluster-tls"
	ingressClusterName    = "ingress-cluster"
	ingressTLSClusterName = "ingress-cluster-tls"
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

func (s *XDSServer) getHttpFilterChainProto(clusterName string, tls bool) *envoy_api_v2_listener.FilterChain {
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
			Name: "envoy.router",
		}},
		StreamIdleTimeout: &duration.Duration{}, // 0 == disabled
		RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_api_v2.RouteConfiguration{
				VirtualHosts: []*envoy_api_v2_route.VirtualHost{{
					Name:    "default_route",
					Domains: []string{"*"},
					Routes: []*envoy_api_v2_route.Route{{
						Match: &envoy_api_v2_route.RouteMatch{
							PathSpecifier: &envoy_api_v2_route.RouteMatch_Prefix{Prefix: "/"},
							Grpc:          &envoy_api_v2_route.RouteMatch_GrpcRouteMatchOptions{},
						},
						Action: &envoy_api_v2_route.Route_Route{
							Route: &envoy_api_v2_route.RouteAction{
								ClusterSpecifier: &envoy_api_v2_route.RouteAction_Cluster{
									Cluster: clusterName,
								},
								Timeout:        &duration.Duration{Seconds: requestTimeout},
								MaxGrpcTimeout: &duration.Duration{Seconds: maxGRPCTimeout},
								RetryPolicy: &envoy_api_v2_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrappers.UInt32Value{Value: numRetries},
									PerTryTimeout: &duration.Duration{Seconds: retryTimeout},
								},
							},
						},
					}, {
						Match: &envoy_api_v2_route.RouteMatch{
							PathSpecifier: &envoy_api_v2_route.RouteMatch_Prefix{Prefix: "/"},
						},
						Action: &envoy_api_v2_route.Route_Route{
							Route: &envoy_api_v2_route.RouteAction{
								ClusterSpecifier: &envoy_api_v2_route.RouteAction_Cluster{
									Cluster: clusterName,
								},
								Timeout: &duration.Duration{Seconds: requestTimeout},
								//IdleTimeout: &duration.Duration{Seconds: idleTimeout},
								RetryPolicy: &envoy_api_v2_route.RetryPolicy{
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

	// Idle timeout can only be specified if non-zero
	if idleTimeout > 0 {
		hcmConfig.GetRouteConfig().VirtualHosts[0].Routes[1].GetRoute().IdleTimeout = &duration.Duration{Seconds: idleTimeout}
	}

	chain := &envoy_api_v2_listener.FilterChain{
		Filters: []*envoy_api_v2_listener.Filter{{
			Name: "cilium.network",
		}, {
			Name: "envoy.http_connection_manager",
			ConfigType: &envoy_api_v2_listener.Filter_TypedConfig{
				TypedConfig: toAny(hcmConfig),
			},
		}},
	}

	if tls {
		chain.FilterChainMatch = &envoy_api_v2_listener.FilterChainMatch{
			TransportProtocol: "tls",
		}
		chain.TransportSocket = &envoy_api_v2_core.TransportSocket{
			Name: "cilium.tls_wrapper",
		}
	}

	return chain
}

func (s *XDSServer) getTcpFilterChainProto(clusterName string) *envoy_api_v2_listener.FilterChain {
	return &envoy_api_v2_listener.FilterChain{
		Filters: []*envoy_api_v2_listener.Filter{{
			Name: "cilium.network",
			ConfigType: &envoy_api_v2_listener.Filter_TypedConfig{
				TypedConfig: toAny(&cilium.NetworkFilter{
					Proxylib: "libcilium.so",
					ProxylibParams: map[string]string{
						"access-log-path": s.accessLogPath,
						"xds-path":        s.socketPath,
					},
				}),
			},
		}, {
			Name: "envoy.tcp_proxy",
			ConfigType: &envoy_api_v2_listener.Filter_TypedConfig{
				TypedConfig: toAny(&envoy_config_tcp.TcpProxy{
					StatPrefix: "tcp_proxy",
					ClusterSpecifier: &envoy_config_tcp.TcpProxy_Cluster{
						Cluster: clusterName,
					},
				}),
			},
		}},
	}
}

// AddListener adds a listener to a running Envoy proxy.
func (s *XDSServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) {
	log.Debugf("Envoy: %s AddListener %s (mayUseOriginalSourceAddr: %v)", kind, name, mayUseOriginalSourceAddr)

	s.mutex.Lock()
	listener := s.listeners[name]
	if listener == nil {
		listener = &Listener{}
		s.listeners[name] = listener
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

	clusterName := egressClusterName
	socketMark := int64(0xB00)
	if isIngress {
		clusterName = ingressClusterName
		socketMark = 0xA00
	}

	listenerConf := &envoy_api_v2.Listener{
		Name: name,
		Address: &envoy_api_v2_core.Address{
			Address: &envoy_api_v2_core.Address_SocketAddress{
				SocketAddress: &envoy_api_v2_core.SocketAddress{
					Protocol:      envoy_api_v2_core.SocketAddress_TCP,
					Address:       "::",
					Ipv4Compat:    true,
					PortSpecifier: &envoy_api_v2_core.SocketAddress_PortValue{PortValue: uint32(port)},
				},
			},
		},
		Transparent: &wrappers.BoolValue{Value: true},
		SocketOptions: []*envoy_api_v2_core.SocketOption{{
			Description: "Listener socket mark",
			Level:       syscall.SOL_SOCKET,
			Name:        syscall.SO_MARK,
			Value:       &envoy_api_v2_core.SocketOption_IntValue{IntValue: socketMark},
			State:       envoy_api_v2_core.SocketOption_STATE_PREBIND,
		}},
		// FilterChains: []*envoy_api_v2_listener.FilterChain
		ListenerFilters: []*envoy_api_v2_listener.ListenerFilter{{
			Name: "cilium.bpf_metadata",
			ConfigType: &envoy_api_v2_listener.ListenerFilter_TypedConfig{
				TypedConfig: toAny(&cilium.BpfMetadata{
					IsIngress:                   isIngress,
					MayUseOriginalSourceAddress: mayUseOriginalSourceAddr,
					BpfRoot:                     bpf.GetMapRoot(),
				}),
			},
		}, {
			Name: "envoy.listener.tls_inspector",
		}},
	}

	// Add filter chains
	if kind == policy.ParserTypeHTTP {
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(clusterName, false))

		// Add a TLS variant
		tlsClusterName := egressTLSClusterName
		if isIngress {
			tlsClusterName = ingressTLSClusterName
		}
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getHttpFilterChainProto(tlsClusterName, true))
	} else {
		listenerConf.FilterChains = append(listenerConf.FilterChains, s.getTcpFilterChainProto(clusterName))
	}

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg,
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
		})
	s.mutex.Unlock()
}

// RemoveListener removes an existing Envoy Listener.
func (s *XDSServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	log.Debugf("Envoy: removeListener %s", name)

	var listenerRevertFunc func(*completion.Completion)

	s.mutex.Lock()
	listener, ok := s.listeners[name]
	if ok && listener != nil {
		listener.count--
		if listener.count == 0 {
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

func getL7Rule(l7 *api.PortRuleL7) *cilium.L7NetworkPolicyRule {
	rule := &cilium.L7NetworkPolicyRule{Rule: make(map[string]string, len(*l7))}

	for k, v := range *l7 {
		rule.Rule[k] = v
	}

	return rule
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

	googleRe2 := &envoy_type_matcher.RegexMatcher_GoogleRe2{
		GoogleRe2: &envoy_type_matcher.RegexMatcher_GoogleRE2{
			MaxProgramSize: &wrappers.UInt32Value{Value: 100}, // Envoy default
		}}

	headers := make([]*envoy_api_v2_route.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{
			Name: ":path",
			HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
					EngineType: googleRe2,
					Regex:      h.Path,
				}}})
	}
	if h.Method != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{
			Name: ":method",
			HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
					EngineType: googleRe2,
					Regex:      h.Method,
				}}})
	}
	if h.Host != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{
			Name: ":authority",
			HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_SafeRegexMatch{
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
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: key,
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: strs[1]}})
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: strs[0],
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_PresentMatch{PresentMatch: true}})
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
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: hdr.Name,
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: ""},
				InvertMatch:          true})
		} else {
			// Header presence and matching (literal) value needed.
			if mismatch_action == cilium.HeaderMatch_FAIL_ON_MISMATCH {
				if value != "" {
					headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: hdr.Name,
						HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: value}})
				} else {
					// Only header presence needed
					headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: hdr.Name,
						HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_PresentMatch{PresentMatch: true}})
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

func createBootstrap(filePath string, name, cluster, version string, xdsSock, egressClusterName, ingressClusterName string, adminPath string) {
	connectTimeout := int64(option.Config.ProxyConnectTimeout) // in seconds

	bs := &envoy_config_bootstrap_v2.Bootstrap{
		Node: &envoy_api_v2_core.Node{Id: name, Cluster: cluster, Metadata: nil, Locality: nil, BuildVersion: version},
		StaticResources: &envoy_config_bootstrap_v2.Bootstrap_StaticResources{
			Clusters: []*envoy_api_v2.Cluster{
				{
					Name:                 egressClusterName,
					ClusterDiscoveryType: &envoy_api_v2.Cluster_Type{Type: envoy_api_v2.Cluster_ORIGINAL_DST},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:      &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:             envoy_api_v2.Cluster_CLUSTER_PROVIDED,
					ProtocolSelection:    envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
				},
				{
					Name:                 egressTLSClusterName,
					ClusterDiscoveryType: &envoy_api_v2.Cluster_Type{Type: envoy_api_v2.Cluster_ORIGINAL_DST},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:      &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:             envoy_api_v2.Cluster_CLUSTER_PROVIDED,
					ProtocolSelection:    envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
					TransportSocket:      &envoy_api_v2_core.TransportSocket{Name: "cilium.tls_wrapper"},
				},
				{
					Name:                 ingressClusterName,
					ClusterDiscoveryType: &envoy_api_v2.Cluster_Type{Type: envoy_api_v2.Cluster_ORIGINAL_DST},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:      &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:             envoy_api_v2.Cluster_CLUSTER_PROVIDED,
					ProtocolSelection:    envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
				},
				{
					Name:                 ingressTLSClusterName,
					ClusterDiscoveryType: &envoy_api_v2.Cluster_Type{Type: envoy_api_v2.Cluster_ORIGINAL_DST},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:      &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:             envoy_api_v2.Cluster_CLUSTER_PROVIDED,
					ProtocolSelection:    envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
					TransportSocket:      &envoy_api_v2_core.TransportSocket{Name: "cilium.tls_wrapper"},
				},
				{
					Name:                 "xds-grpc-cilium",
					ClusterDiscoveryType: &envoy_api_v2.Cluster_Type{Type: envoy_api_v2.Cluster_STATIC},
					ConnectTimeout:       &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					LbPolicy:             envoy_api_v2.Cluster_ROUND_ROBIN,
					LoadAssignment: &envoy_api_v2.ClusterLoadAssignment{
						ClusterName: "xds-grpc-cilium",
						Endpoints: []*envoy_api_v2_endpoint.LocalityLbEndpoints{{
							LbEndpoints: []*envoy_api_v2_endpoint.LbEndpoint{{
								HostIdentifier: &envoy_api_v2_endpoint.LbEndpoint_Endpoint{
									Endpoint: &envoy_api_v2_endpoint.Endpoint{
										Address: &envoy_api_v2_core.Address{
											Address: &envoy_api_v2_core.Address_Pipe{
												Pipe: &envoy_api_v2_core.Pipe{Path: xdsSock}},
										},
									},
								},
							}},
						}},
					},
					Http2ProtocolOptions: &envoy_api_v2_core.Http2ProtocolOptions{},
				},
			},
		},
		DynamicResources: &envoy_config_bootstrap_v2.Bootstrap_DynamicResources{
			LdsConfig: &envoy_api_v2_core.ConfigSource{
				ConfigSourceSpecifier: &envoy_api_v2_core.ConfigSource_ApiConfigSource{
					ApiConfigSource: &envoy_api_v2_core.ApiConfigSource{
						ApiType: envoy_api_v2_core.ApiConfigSource_GRPC,
						GrpcServices: []*envoy_api_v2_core.GrpcService{
							{
								TargetSpecifier: &envoy_api_v2_core.GrpcService_EnvoyGrpc_{
									EnvoyGrpc: &envoy_api_v2_core.GrpcService_EnvoyGrpc{
										ClusterName: "xds-grpc-cilium",
									},
								},
							},
						},
					},
				},
			},
		},
		Admin: &envoy_config_bootstrap_v2.Admin{
			AccessLogPath: "/dev/null",
			Address: &envoy_api_v2_core.Address{
				Address: &envoy_api_v2_core.Address_Pipe{
					Pipe: &envoy_api_v2_core.Pipe{Path: adminPath},
				},
			},
		},
	}

	log.Debugf("Envoy: Bootstrap: %s", bs)
	data, err := proto.Marshal(bs)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error marshaling Envoy bootstrap")
	}
	err = ioutil.WriteFile(filePath, data, 0644)
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

func getPortNetworkPolicyRule(sel policy.CachedSelector, l7Parser policy.L7ParserType, l7Rules *policy.PerSelectorPolicy) (*cilium.PortNetworkPolicyRule, bool) {
	// Optimize the policy if the endpoint selector is a wildcard by
	// keeping remote policies list empty to match all remote policies.
	var remotePolicies []uint64
	if !sel.IsWildcard() {
		for _, id := range sel.GetSelections() {
			remotePolicies = append(remotePolicies, uint64(id))
		}

		// No remote policies would match this rule. Discard it.
		if len(remotePolicies) == 0 {
			return nil, true
		}

		sort.Slice(remotePolicies, func(i, j int) bool {
			return remotePolicies[i] < remotePolicies[j]
		})
	}

	r := &cilium.PortNetworkPolicyRule{
		RemotePolicies: remotePolicies,
	}

	if l7Rules == nil {
		// L3/L4 only rule, everything in L7 is allowed
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
		// TODO: Support Kafka. For now, just ignore any Kafka L7 rule.

	case policy.ParserTypeDNS:
		// TODO: Support DNS. For now, just ignore any DNS L7 rule.

	default:
		// Assume unknown parser types use a Key-Value Pair policy
		if len(l7Rules.L7) > 0 {
			kvpRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules.L7))
			for _, l7 := range l7Rules.L7 {
				kvpRules = append(kvpRules, getL7Rule(&l7))
			}
			// L7 rules are not sorted
			r.L7Proto = l7Parser.String()
			r.L7 = &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: &cilium.L7NetworkPolicyRules{
					L7Rules: kvpRules,
				},
			}
		}
	}

	return r, canShortCircuit
}

func getWildcardNetworkPolicyRule(selectors policy.L7DataMap) *cilium.PortNetworkPolicyRule {
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

		if l7 != nil {
			log.Warning("Wildcard L4 L7DataMap has L7 rules!")
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

func getDirectionNetworkPolicy(l4Policy policy.L4PolicyMap, policyEnforced bool) []*cilium.PortNetworkPolicy {
	if !policyEnforced {
		// Return an allow-all policy.
		return allowAllPortNetworkPolicy
	}

	if len(l4Policy) == 0 {
		return nil
	}

	PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, len(l4Policy))

	for _, l4 := range l4Policy {
		var protocol envoy_api_v2_core.SocketAddress_Protocol
		switch l4.Protocol {
		case api.ProtoTCP:
			protocol = envoy_api_v2_core.SocketAddress_TCP
		case api.ProtoUDP:
			protocol = envoy_api_v2_core.SocketAddress_UDP
		}

		pnp := &cilium.PortNetworkPolicy{
			Port:     uint32(l4.Port),
			Protocol: protocol,
			Rules:    make([]*cilium.PortNetworkPolicyRule, 0, len(l4.L7RulesPerSelector)),
		}
		allowAll := false
		// Assume none of the rules have side-effects so that rule evaluation can
		// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
		// is set to 'false' below if any rules with side effects are encountered,
		// causing all the applicable rules to be evaluated instead.
		canShortCircuit := true

		if l4.Port == 0 {
			// Wildcard L4 rule, must generate L7 allow-all in case there are other
			// port-specific rules. Otherwise traffic from allowed remotes could be dropped.
			rule := getWildcardNetworkPolicyRule(l4.L7RulesPerSelector)
			if rule != nil {
				if len(rule.RemotePolicies) == 0 && rule.L7 == nil {
					// Got an allow-all rule, which can short-circuit all of
					// the other rules.
					allowAll = true
				}
				pnp.Rules = append(pnp.Rules, rule)
			}
		} else {
			for sel, l7 := range l4.L7RulesPerSelector {
				rule, cs := getPortNetworkPolicyRule(sel, l4.L7Parser, l7)
				if rule != nil {
					if !cs {
						canShortCircuit = false
					}
					if len(rule.RemotePolicies) == 0 && rule.L7 == nil {
						// Got an allow-all rule, which can short-circuit all of
						// the other rules.
						allowAll = true
					}
					pnp.Rules = append(pnp.Rules, rule)
				}
			}
		}
		// Short-circuit rules if a rule allows all and all other rules can be short-circuited
		if allowAll && canShortCircuit {
			log.Debug("Short circuiting HTTP rules due to rule allowing all and no other rules needing attention")
			pnp.Rules = nil
		}

		// No rule for this port matches any remote identity.
		// This means that no traffic was explicitly allowed for this port.
		// In this case, just don't generate any PortNetworkPolicy for this
		// port.
		if !allowAll && len(pnp.Rules) == 0 {
			continue
		}

		SortPortNetworkPolicyRules(pnp.Rules)

		PerPortPolicies = append(PerPortPolicies, pnp)
	}

	if len(PerPortPolicies) == 0 {
		return nil
	}

	SortPortNetworkPolicies(PerPortPolicies)

	return PerPortPolicies
}

// getNetworkPolicy converts a network policy into a cilium.NetworkPolicy.
func getNetworkPolicy(name string, id identity.NumericIdentity, conntrackName string, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		Name:             name,
		Policy:           uint64(id),
		ConntrackMapName: conntrackName,
	}

	// If no policy, deny all traffic. Otherwise, convert the policies for ingress and egress.
	if policy != nil {
		p.IngressPerPortPolicies = getDirectionNetworkPolicy(policy.Ingress, ingressPolicyEnforced)
		p.EgressPerPortPolicies = getDirectionNetworkPolicy(policy.Egress, egressPolicyEnforced)
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
	var policies []*cilium.NetworkPolicy
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		networkPolicy := getNetworkPolicy(ip, ep.GetIdentity(), ep.ConntrackNameLocked(), policy,
			ingressPolicyEnforced, egressPolicyEnforced)
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
		if len(s.listeners) == 0 {
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
	if !ep.HasSidecarProxy() && len(s.listeners) == 0 {
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
