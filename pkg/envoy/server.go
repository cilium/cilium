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
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/cilium/proxy/go/cilium/api"
	envoy_api_v2 "github.com/cilium/proxy/go/envoy/api/v2"
	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	envoy_api_v2_listener "github.com/cilium/proxy/go/envoy/api/v2/listener"
	envoy_api_v2_route "github.com/cilium/proxy/go/envoy/api/v2/route"
	envoy_config_bootstrap_v2 "github.com/cilium/proxy/go/envoy/config/bootstrap/v2"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/struct"
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
	egressClusterName  = "egress-cluster"
	ingressClusterName = "ingress-cluster"
)

// XDSServer provides a high-lever interface to manage resources published
// using the xDS gRPC API.
type XDSServer struct {
	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// mutex protects accesses to the configuration resources.
	mutex lock.RWMutex

	// listenerProto is a generic Envoy Listener protobuf. Immutable.
	listenerProto *envoy_api_v2.Listener

	// httpFilterChainProto is a generic Envoy HTTP connection manager filter chain protobuf. Immutable.
	httpFilterChainProto *envoy_api_v2_listener.FilterChain

	// tcpFilterChainProto is a generic Envoy TCP proxy filter chain protobuf. Immutable.
	tcpFilterChainProto *envoy_api_v2_listener.FilterChain

	// listenerMutator publishes listener updates to Envoy proxies.
	listenerMutator xds.AckingResourceMutator

	// listeners is the set of names of listeners that have been added by
	// calling AddListener.
	// mutex must be held when accessing this.
	// Value hold the number of redirects using this listener.
	listeners map[string]uint

	// networkPolicyCache publishes network policy configuration updates to
	// Envoy proxies.
	networkPolicyCache *xds.Cache

	// NetworkPolicyMutator wraps networkPolicyCache to publish route
	// configuration updates to Envoy proxies.
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

// StartXDSServer configures and starts the xDS GRPC server.
func StartXDSServer(stateDir string) *XDSServer {
	xdsPath := getXDSPath(stateDir)
	accessLogPath := getAccessLogPath(stateDir)
	denied403body := option.Config.HTTP403Message
	requestTimeout := option.Config.HTTPRequestTimeout // seconds
	idleTimeout := option.Config.HTTPIdleTimeout       // seconds
	maxGRPCTimeout := option.Config.HTTPMaxGRPCTimeout // seconds
	numRetries := option.Config.HTTPRetryCount
	retryTimeout := option.Config.HTTPRetryTimeout //seconds

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
	ldsMutator := xds.NewAckingResourceMutatorWrapper(ldsCache, xds.IstioNodeToIP)
	ldsConfig := &xds.ResourceTypeConfiguration{
		Source:      ldsCache,
		AckObserver: ldsMutator,
	}

	npdsCache := xds.NewCache()
	npdsMutator := xds.NewAckingResourceMutatorWrapper(npdsCache, xds.IstioNodeToIP)
	npdsConfig := &xds.ResourceTypeConfiguration{
		Source:      npdsCache,
		AckObserver: npdsMutator,
	}

	nphdsConfig := &xds.ResourceTypeConfiguration{
		Source:      NetworkPolicyHostsCache,
		AckObserver: nil, // We don't wait for ACKs for those resources.
	}

	stopServer := startXDSGRPCServer(socketListener, ldsConfig, npdsConfig, nphdsConfig, 5*time.Second)

	listenerProto := &envoy_api_v2.Listener{
		Address: &envoy_api_v2_core.Address{
			Address: &envoy_api_v2_core.Address_SocketAddress{
				SocketAddress: &envoy_api_v2_core.SocketAddress{
					Protocol:   envoy_api_v2_core.SocketAddress_TCP,
					Address:    "::",
					Ipv4Compat: true,
					// PortSpecifier: &envoy_api_v2_core.SocketAddress_PortValue{0},
				},
			},
		},
		// FilterChains: []*envoy_api_v2_listener.FilterChain
		ListenerFilters: []*envoy_api_v2_listener.ListenerFilter{{
			Name: "cilium.bpf_metadata",
			ConfigType: &envoy_api_v2_listener.ListenerFilter_Config{
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"is_ingress": {Kind: &structpb.Value_BoolValue{BoolValue: false}},
					"bpf_root":   {Kind: &structpb.Value_StringValue{StringValue: bpf.GetMapRoot()}},
				}},
			},
		}},
	}

	httpFilterChainProto := &envoy_api_v2_listener.FilterChain{
		Filters: []*envoy_api_v2_listener.Filter{{
			Name: "cilium.network",
		}, {
			Name: "envoy.http_connection_manager",
			ConfigType: &envoy_api_v2_listener.Filter_Config{
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"stat_prefix": {Kind: &structpb.Value_StringValue{StringValue: "proxy"}},
					"http_filters": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name": {Kind: &structpb.Value_StringValue{StringValue: "cilium.l7policy"}},
							"config": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"access_log_path": {Kind: &structpb.Value_StringValue{StringValue: accessLogPath}},
								"denied_403_body": {Kind: &structpb.Value_StringValue{StringValue: denied403body}},
							}}}},
						}}}},
						{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name":   {Kind: &structpb.Value_StringValue{StringValue: "envoy.router"}},
							"config": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{}}}},
						}}}},
					}}}},
					"stream_idle_timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{}}}},
					"route_config": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
						"virtual_hosts": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
							{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"name": {Kind: &structpb.Value_StringValue{StringValue: "default_route"}},
								"domains": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
									{Kind: &structpb.Value_StringValue{StringValue: "*"}},
								}}}},
								"routes": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
									{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
										"match": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											"prefix": {Kind: &structpb.Value_StringValue{StringValue: "/"}},
											"grpc":   {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{}}}},
										}}}},
										"route": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											// "cluster":          {Kind: &structpb.Value_StringValue{StringValue: "cluster1"}},
											"timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
												"seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(requestTimeout)}},
											}}}},
											"max_grpc_timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
												"seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(maxGRPCTimeout)}},
											}}}},
											"retry_policy": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
												"retry_on":    {Kind: &structpb.Value_StringValue{StringValue: "5xx"}},
												"num_retries": {Kind: &structpb.Value_NumberValue{NumberValue: float64(numRetries)}},
												"per_try_timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
													"seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(retryTimeout)}},
												}}}},
											}}}},
										}}}},
									}}}},
									{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
										"match": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											"prefix": {Kind: &structpb.Value_StringValue{StringValue: "/"}},
										}}}},
										"route": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											// "cluster":          {Kind: &structpb.Value_StringValue{StringValue: "cluster1"}},
											"timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
												"seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(requestTimeout)}},
											}}}},
											// "idle_timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											// "seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(idleTimeout)}},
											// }}}},
											"retry_policy": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
												"retry_on":    {Kind: &structpb.Value_StringValue{StringValue: "5xx"}},
												"num_retries": {Kind: &structpb.Value_NumberValue{NumberValue: float64(numRetries)}},
												"per_try_timeout": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
													"seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(retryTimeout)}},
												}}}},
											}}}},
										}}}},
									}}}},
								}}}},
							}}}},
						}}}},
					}}}},
				}},
			},
		}},
	}

	// Idle timeout can only be specified if non-zero
	if idleTimeout > 0 {
		httpFilterChainProto.Filters[1].ConfigType.(*envoy_api_v2_listener.Filter_Config).Config.Fields["route_config"].GetStructValue().Fields["virtual_hosts"].GetListValue().Values[0].GetStructValue().Fields["routes"].GetListValue().Values[1].GetStructValue().Fields["route"].GetStructValue().Fields["idle_timeout"] = &structpb.Value{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{"seconds": {Kind: &structpb.Value_NumberValue{NumberValue: float64(idleTimeout)}}}}}}
	}

	tcpFilterChainProto := &envoy_api_v2_listener.FilterChain{
		Filters: []*envoy_api_v2_listener.Filter{{
			Name: "cilium.network",
			ConfigType: &envoy_api_v2_listener.Filter_Config{
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"proxylib": {Kind: &structpb.Value_StringValue{StringValue: "libcilium.so"}},
					"proxylib_params": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
						"access-log-path": {Kind: &structpb.Value_StringValue{StringValue: accessLogPath}},
						"xds-path":        {Kind: &structpb.Value_StringValue{StringValue: xdsPath}},
					}}}},
					// "l7_proto": {Kind: &structpb.Value_StringValue{StringValue: "parsername"}},
					// "policy_name": {Kind: &structpb.Value_StringValue{StringValue: "1.2.3.4"}},
				}},
			},
		}, {
			Name: "envoy.tcp_proxy",
			ConfigType: &envoy_api_v2_listener.Filter_Config{
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"stat_prefix": {Kind: &structpb.Value_StringValue{StringValue: "tcp_proxy"}},
					// "cluster":     {Kind: &structpb.Value_StringValue{StringValue: "cluster1"}},
				}},
			},
		}},
	}

	return &XDSServer{
		socketPath:             xdsPath,
		listenerProto:          listenerProto,
		httpFilterChainProto:   httpFilterChainProto,
		tcpFilterChainProto:    tcpFilterChainProto,
		listenerMutator:        ldsMutator,
		listeners:              make(map[string]uint),
		networkPolicyCache:     npdsCache,
		NetworkPolicyMutator:   npdsMutator,
		networkPolicyEndpoints: make(map[string]logger.EndpointUpdater),
		stopServer:             stopServer,
	}
}

// AddListener adds a listener to a running Envoy proxy.
func (s *XDSServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, wg *completion.WaitGroup) {
	log.Debugf("Envoy: %s AddListener %s", kind, name)

	s.mutex.Lock()
	count, ok := s.listeners[name]
	s.listeners[name] = count + 1
	if ok && count > 0 {
		log.Debugf("Envoy: Reusing listener: %s", name)
		s.mutex.Unlock()
		return
	}
	s.mutex.Unlock()

	clusterName := egressClusterName
	if isIngress {
		clusterName = ingressClusterName
	}

	// Fill in the listener-specific parts.
	listenerConf := proto.Clone(s.listenerProto).(*envoy_api_v2.Listener)
	if kind == policy.ParserTypeHTTP {
		listenerConf.FilterChains = append(listenerConf.FilterChains, proto.Clone(s.httpFilterChainProto).(*envoy_api_v2_listener.FilterChain))
		// listenerConf.FilterChains[0].Filters[1].ConfigType.(*envoy_api_v2_listener.Filter_Config).Config.Fields["http_filters"].GetListValue().Values[0].GetStructValue().Fields["config"].GetStructValue().Fields["policy_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: endpointPolicyName}}
		routes := listenerConf.FilterChains[0].Filters[1].ConfigType.(*envoy_api_v2_listener.Filter_Config).Config.Fields["route_config"].GetStructValue().Fields["virtual_hosts"].GetListValue().Values[0].GetStructValue().Fields["routes"].GetListValue().Values
		routes[0].GetStructValue().Fields["route"].GetStructValue().Fields["cluster"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: clusterName}}
		routes[1].GetStructValue().Fields["route"].GetStructValue().Fields["cluster"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: clusterName}}
	} else {
		listenerConf.FilterChains = append(listenerConf.FilterChains, proto.Clone(s.tcpFilterChainProto).(*envoy_api_v2_listener.FilterChain))
		// listenerConf.FilterChains[0].Filters[0].ConfigType.(*envoy_api_v2_listener.Filter_Config).Config.Fields["policy_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: endpointPolicyName}}
		// listenerConf.FilterChains[0].Filters[0].ConfigType.(*envoy_api_v2_listener.Filter_Config).Config.Fields["l7_proto"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: kind.String()}}
		listenerConf.FilterChains[0].Filters[1].ConfigType.(*envoy_api_v2_listener.Filter_Config).Config.Fields["cluster"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: clusterName}}
	}

	listenerConf.Name = name
	listenerConf.Address.GetSocketAddress().PortSpecifier = &envoy_api_v2_core.SocketAddress_PortValue{PortValue: uint32(port)}
	if isIngress {
		listenerConf.ListenerFilters[0].ConfigType.(*envoy_api_v2_listener.ListenerFilter_Config).Config.Fields["is_ingress"].GetKind().(*structpb.Value_BoolValue).BoolValue = true
	}

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg.AddCompletion())
}

// RemoveListener removes an existing Envoy Listener.
func (s *XDSServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	s.mutex.Lock()

	var listenerRevertFunc func(*completion.Completion)

	log.Debugf("Envoy: removeListener %s", name)
	if count, ok := s.listeners[name]; ok && count > 0 {
		if count == 1 {
			delete(s.listeners, name)
			listenerRevertFunc = s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg.AddCompletion())
		} else {
			s.listeners[name] = count - 1
		}
	} else {
		// Bail out if this listener does not exist
		log.Fatalf("Envoy: Attempt to remove non-existent listener: %s", name)
	}
	s.mutex.Unlock()

	return func(completion *completion.Completion) {
		s.mutex.Lock()
		s.listeners[name] = s.listeners[name] + 1
		s.mutex.Unlock()

		if listenerRevertFunc != nil {
			listenerRevertFunc(completion)
		}
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

	return rule // No ruleRef
}

func getHTTPRule(h *api.PortRuleHTTP) (headers []*envoy_api_v2_route.HeaderMatcher, ruleRef string) {
	// Count the number of header matches we need
	cnt := len(h.Headers)
	if h.Path != "" {
		cnt++
	}
	if h.Method != "" {
		cnt++
	}
	if h.Host != "" {
		cnt++
	}

	headers = make([]*envoy_api_v2_route.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: ":path",
			HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: h.Path}})
		ruleRef = `PathRegexp("` + h.Path + `")`
	}
	if h.Method != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: ":method",
			HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: h.Method}})
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `MethodRegexp("` + h.Method + `")`
	}

	if h.Host != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: ":authority",
			HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: h.Host}})
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `HostRegexp("` + h.Host + `")`
	}
	for _, hdr := range h.Headers {
		strs := strings.SplitN(hdr, " ", 2)
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `Header("`
		if len(strs) == 2 {
			// Remove ':' in "X-Key: true"
			key := strings.TrimRight(strs[0], ":")
			// Header presence and matching (literal) value needed.
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: key,
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: strs[1]}})
			ruleRef += key + `","` + strs[1]
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: strs[0],
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_PresentMatch{PresentMatch: true}})
			ruleRef += strs[0]
		}
		ruleRef += `")`
	}
	if len(headers) == 0 {
		headers = nil
	} else {
		SortHeaderMatchers(headers)
	}
	return
}

func createBootstrap(filePath string, name, cluster, version string, xdsSock, egressClusterName, ingressClusterName string, adminPath string) {
	connectTimeout := int64(option.Config.ProxyConnectTimeout) // in seconds

	bs := &envoy_config_bootstrap_v2.Bootstrap{
		Node: &envoy_api_v2_core.Node{Id: name, Cluster: cluster, Metadata: nil, Locality: nil, BuildVersion: version},
		StaticResources: &envoy_config_bootstrap_v2.Bootstrap_StaticResources{
			Clusters: []*envoy_api_v2.Cluster{
				{
					Name:              egressClusterName,
					Type:              envoy_api_v2.Cluster_ORIGINAL_DST,
					ConnectTimeout:    &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:   &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:          envoy_api_v2.Cluster_ORIGINAL_DST_LB,
					ProtocolSelection: envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
				},
				{
					Name:              ingressClusterName,
					Type:              envoy_api_v2.Cluster_ORIGINAL_DST,
					ConnectTimeout:    &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					CleanupInterval:   &duration.Duration{Seconds: connectTimeout, Nanos: 500000000},
					LbPolicy:          envoy_api_v2.Cluster_ORIGINAL_DST_LB,
					ProtocolSelection: envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
				},
				{
					Name:           "xds-grpc-cilium",
					Type:           envoy_api_v2.Cluster_STATIC,
					ConnectTimeout: &duration.Duration{Seconds: connectTimeout, Nanos: 0},
					LbPolicy:       envoy_api_v2.Cluster_ROUND_ROBIN,
					Hosts: []*envoy_api_v2_core.Address{
						{
							Address: &envoy_api_v2_core.Address_Pipe{
								Pipe: &envoy_api_v2_core.Pipe{Path: xdsSock}},
						},
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

func getPortNetworkPolicyRule(sel api.EndpointSelector, l7Parser policy.L7ParserType, l7Rules api.L7Rules,
	labelsMap, deniedIdentities cache.IdentityCache) *cilium.PortNetworkPolicyRule {
	// In case the endpoint selector is a wildcard and there are no denied
	// identities, optimize the policy by setting an empty remote policies list
	// to match all remote policies.
	var remotePolicies []uint64
	if !sel.IsWildcard() || len(deniedIdentities) > 0 {
		for id, labels := range labelsMap {
			_, ok := deniedIdentities[id]
			if !ok && sel.Matches(labels) {
				remotePolicies = append(remotePolicies, uint64(id))
			}
		}

		// No remote policies would match this rule. Discard it.
		if len(remotePolicies) == 0 {
			return nil
		}

		sort.Slice(remotePolicies, func(i, j int) bool {
			return remotePolicies[i] < remotePolicies[j]
		})
	}

	r := &cilium.PortNetworkPolicyRule{
		RemotePolicies: remotePolicies,
	}

	switch l7Parser {
	case policy.ParserTypeHTTP:
		if len(l7Rules.HTTP) > 0 { // Just cautious. This should never be false.
			httpRules := make([]*cilium.HttpNetworkPolicyRule, 0, len(l7Rules.HTTP))
			for _, l7 := range l7Rules.HTTP {
				headers, _ := getHTTPRule(&l7)
				httpRules = append(httpRules, &cilium.HttpNetworkPolicyRule{Headers: headers})
			}
			SortHTTPNetworkPolicyRules(httpRules)
			r.L7 = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: &cilium.HttpNetworkPolicyRules{
					HttpRules: httpRules,
				},
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

	return r
}

func getDirectionNetworkPolicy(l4Policy policy.L4PolicyMap, policyEnforced bool,
	labelsMap, deniedIdentities cache.IdentityCache) []*cilium.PortNetworkPolicy {
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
			Rules:    make([]*cilium.PortNetworkPolicyRule, 0, len(l4.L7RulesPerEp)),
		}

		allowAll := false
		for sel, l7 := range l4.L7RulesPerEp {
			rule := getPortNetworkPolicyRule(sel, l4.L7Parser, l7, labelsMap, deniedIdentities)
			if rule != nil {
				if len(rule.RemotePolicies) == 0 && rule.L7 == nil {
					// Got an allow-all rule, which would short-circuit all of
					// the other rules. Just set no rules, which has the same
					// effect of allowing all.
					allowAll = true
					pnp.Rules = nil
					break
				}

				pnp.Rules = append(pnp.Rules, rule)
			}
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
func getNetworkPolicy(name string, id identity.NumericIdentity, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool, labelsMap,
	deniedIngressIdentities, deniedEgressIdentities cache.IdentityCache) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		Name:   name,
		Policy: uint64(id),
	}

	// If no policy, deny all traffic. Otherwise, convert the policies for ingress and egress.
	if policy != nil {
		p.IngressPerPortPolicies = getDirectionNetworkPolicy(policy.Ingress, ingressPolicyEnforced, labelsMap, deniedIngressIdentities)
		p.EgressPerPortPolicies = getDirectionNetworkPolicy(policy.Egress, egressPolicyEnforced, labelsMap, deniedEgressIdentities)
	}

	return p
}

// UpdateNetworkPolicy adds or updates a network policy in the set published
// to L7 proxies.
// When the proxy acknowledges the network policy update, it will result in
// a subsequent call to the endpoint's OnProxyPolicyUpdate() function.
func (s *XDSServer) UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool, labelsMap,
	deniedIngressIdentities, deniedEgressIdentities cache.IdentityCache, wg *completion.WaitGroup) (error, func() error) {

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
		networkPolicy := getNetworkPolicy(ip, ep.GetIdentity(), policy, ingressPolicyEnforced, egressPolicyEnforced,
			labelsMap, deniedIngressIdentities, deniedEgressIdentities)
		err := networkPolicy.Validate()
		if err != nil {
			return fmt.Errorf("error validating generated NetworkPolicy for %s: %s", ip, err), nil
		}
		policies = append(policies, networkPolicy)
	}

	if ep.HasSidecarProxy() { // Use sidecar proxy.
		// If there are no L7 rules, we expect Envoy to NOT be configured with
		// an L7 filter, in which case we'd never receive an ACK for the policy,
		// and we'd wait forever.
		// TODO: Remove this when we implement and inject an Envoy network filter
		// into every Envoy listener to filter at L3/L4.
		var hasL7Rules bool
	Policies:
		for _, p := range policies {
			for _, pnp := range p.IngressPerPortPolicies {
				for _, r := range pnp.Rules {
					if r.L7 != nil {
						hasL7Rules = true
						break Policies
					}
				}
			}
			for _, pnp := range p.EgressPerPortPolicies {
				for _, r := range pnp.Rules {
					if r.L7 != nil {
						hasL7Rules = true
						break Policies
					}
				}
			}
		}
		if !hasL7Rules {
			wg = nil
		}
	} else { // Use node proxy.
		// If there are no listeners configured, the local node's Envoy proxy won't
		// query for network policies and therefore will never ACK them, and we'd
		// wait forever.
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
		var c *completion.Completion
		if wg != nil {
			c = wg.AddCompletionWithCallback(callback)
		}
		nodeIDs := make([]string, 0, 1)
		if ep.HasSidecarProxy() {
			if ep.GetIPv4Address() == "" {
				log.Fatal("Envoy: Sidecar proxy has no IPv4 address")
			}
			nodeIDs = append(nodeIDs, ep.GetIPv4Address())
		} else {
			nodeIDs = append(nodeIDs, "127.0.0.1")
		}
		revertFuncs = append(revertFuncs, s.NetworkPolicyMutator.Upsert(NetworkPolicyTypeURL, p.Name, p, nodeIDs, c))
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

// RemoveNetworkPolicy removes network policies relevant to the specified
// endpoint from the set published to L7 proxies, and stops listening for
// acks for policies on this endpoint.
func (s *XDSServer) RemoveNetworkPolicy(ep logger.EndpointInfoSource) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if ep.GetIPv6Address() != "" {
		name := ep.GetIPv6Address()
		s.networkPolicyCache.Delete(NetworkPolicyTypeURL, name, false)
		delete(s.networkPolicyEndpoints, name)
	}
	if ep.GetIPv4Address() != "" {
		name := ep.GetIPv4Address()
		s.networkPolicyCache.Delete(NetworkPolicyTypeURL, name, false)
		delete(s.networkPolicyEndpoints, name)
	}
}

// RemoveAllNetworkPolicies removes all network policies from the set published
// to L7 proxies.
func (s *XDSServer) RemoveAllNetworkPolicies() {
	s.networkPolicyCache.Clear(NetworkPolicyTypeURL, false)
}

// GetNetworkPolicies returns the current version of the network policies with
// the given names.
// If resourceNames is empty, all resources are returned.
func (s *XDSServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	resources, err := s.networkPolicyCache.GetResources(context.Background(), NetworkPolicyTypeURL, 0, nil, resourceNames)
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
