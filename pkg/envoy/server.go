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
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_listener "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/listener"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	envoy_config_bootstrap_v2 "github.com/cilium/cilium/pkg/envoy/envoy/config/bootstrap/v2"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/golang/protobuf/ptypes/wrappers"
)

// allowAction is a "Pass" route action to use in route rules. Immutable.
var envoyRouteAllowAction = &envoy_api_v2_route.Route_Route{Route: &envoy_api_v2_route.RouteAction{
	ClusterSpecifier: &envoy_api_v2_route.RouteAction_Cluster{Cluster: "cluster1"},
}}

// XDSServer provides a high-lever interface to manage resources published
// using the xDS gRPC API.
type XDSServer struct {
	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// mutex protects accesses to the configuration resources.
	mutex lock.RWMutex

	// listenerProto is a generic Envoy Listener protobuf. Immutable.
	listenerProto *envoy_api_v2.Listener

	// loggers maps a listener resource name to its Logger.
	loggers map[string]Logger

	// listenerMutator publishes udpates to listeners to Envoy proxies.
	listenerMutator xds.AckingResourceMutator

	// listenerMutator publishes udpates to route configurations to Envoy
	// proxies.
	routeMutator xds.AckingResourceMutator

	// stopServer stops the xDS gRPC server.
	stopServer context.CancelFunc
}

func createXDSServer(path, accessLogPath string) *XDSServer {
	os.Remove(path)
	socketListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", path)
	}

	listenerCache := xds.NewCache()
	listenerMutator := xds.NewAckingResourceMutatorWrapper(listenerCache, xds.IstioNodeToIP)
	ldsConfig := &xds.ResourceTypeConfiguration{
		Source:      listenerCache,
		AckObserver: listenerMutator,
	}

	routeCache := xds.NewCache()
	routeMutator := xds.NewAckingResourceMutatorWrapper(routeCache, xds.IstioNodeToIP)
	rdsConfig := &xds.ResourceTypeConfiguration{
		Source:      routeCache,
		AckObserver: routeMutator,
	}

	stopServer := StartXDSGRPCServer(socketListener, ldsConfig, rdsConfig, 5*time.Second)

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
		FilterChains: []*envoy_api_v2_listener.FilterChain{{
			Filters: []*envoy_api_v2_listener.Filter{{
				Name: "envoy.http_connection_manager",
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"stat_prefix": {&structpb.Value_StringValue{StringValue: "proxy"}},
					"http_filters": {&structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name": {&structpb.Value_StringValue{StringValue: "cilium.l7policy"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"access_log_path": {&structpb.Value_StringValue{StringValue: accessLogPath}},
							}}}},
						}}}},
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name":   {&structpb.Value_StringValue{StringValue: "envoy.router"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{}}}},
						}}}},
					}}}},
					"rds": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
						"config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"api_config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"api_type":      {&structpb.Value_NumberValue{NumberValue: float64(envoy_api_v2_core.ApiConfigSource_GRPC)}},
								"cluster_names": {&structpb.Value_StringValue{StringValue: "xdsCluster"}},
							}}}},
						}}}},
						// "route_config_name": {&structpb.Value_StringValue{StringValue: "route_config_name"}},
					}}}},
				}},
			}},
		}},
		ListenerFilters: []*envoy_api_v2_listener.ListenerFilter{{
			Name: "cilium.bpf_metadata",
			Config: &structpb.Struct{Fields: map[string]*structpb.Value{
				"is_ingress": {&structpb.Value_BoolValue{BoolValue: false}},
				"bpf_root":   {&structpb.Value_StringValue{StringValue: "/sys/fs/bpf"}},
				"identity":   {&structpb.Value_NumberValue{NumberValue: float64(0)}},
			}},
		}},
	}

	return &XDSServer{
		socketPath:      path,
		listenerProto:   listenerProto,
		loggers:         make(map[string]Logger),
		listenerMutator: listenerMutator,
		routeMutator:    routeMutator,
		stopServer:      stopServer,
	}
}

func (s *XDSServer) addListener(name string, port uint16, l7rules policy.L7DataMap, isIngress bool, logger Logger, wg *completion.WaitGroup) {
	log.Debug("Envoy: addListener ", name)

	s.mutex.Lock()

	// Bail out if this listener already exists
	if _, ok := s.loggers[name]; ok {
		log.Fatalf("Envoy: addListener: Listener %s already exists!", name)
	}

	s.loggers[name] = logger

	s.mutex.Unlock()

	s.routeMutator.Upsert(RouteConfigurationTypeURL, name, getRouteConfiguration(name, l7rules),
		[]string{"127.0.0.1"}, wg.AddCompletion())

	// Fill in the listener-specific parts.
	listenerConf := proto.Clone(s.listenerProto).(*envoy_api_v2.Listener)
	listenerConf.Name = name
	listenerConf.Address.GetSocketAddress().PortSpecifier = &envoy_api_v2_core.SocketAddress_PortValue{PortValue: uint32(port)}
	listenerConf.FilterChains[0].Filters[0].Config.Fields["rds"].GetStructValue().Fields["route_config_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: name}}
	if isIngress {
		listenerConf.ListenerFilters[0].Config.Fields["is_ingress"].GetKind().(*structpb.Value_BoolValue).BoolValue = true
	}

	listenerConf.FilterChains[0].Filters[0].Config.Fields["http_filters"].GetListValue().Values[0].GetStructValue().Fields["config"].GetStructValue().Fields["listener_id"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: name}}

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg.AddCompletion())
}

func (s *XDSServer) updateListener(name string, l7rules policy.L7DataMap, wg *completion.WaitGroup) {
	s.mutex.Lock()
	log.Debug("Envoy: updateListener ", name)
	l := s.loggers[name]
	// Bail out if this listener does not exist
	if l == nil {
		log.Fatalf("Envoy: updateListener: Listener %s does not exist", name)
	}
	s.mutex.Unlock()

	s.routeMutator.Upsert(RouteConfigurationTypeURL, name, getRouteConfiguration(name, l7rules),
		[]string{"127.0.0.1"}, wg.AddCompletion())
}

func (s *XDSServer) removeListener(name string, wg *completion.WaitGroup) {
	s.mutex.Lock()
	log.Debug("Envoy: removeListener ", name)
	l := s.loggers[name]
	// Bail out if this listener does not exist
	if l == nil {
		log.Fatalf("Envoy: removeListener: Listener %s does not exist", name)
	}
	delete(s.loggers, name)
	s.mutex.Unlock()

	s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg.AddCompletion())

	s.routeMutator.Delete(RouteConfigurationTypeURL, name, []string{"127.0.0.1"}, wg.AddCompletion())
}

// Find the listener given the Envoy Resource name
func (s *XDSServer) findListenerLogger(name string) Logger {
	if s == nil {
		return nil
	}
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.loggers[name]
}

func (s *XDSServer) stop() {
	s.stopServer()
	os.Remove(s.socketPath)
}

func translatePolicyRule(h api.PortRuleHTTP) *envoy_api_v2_route.Route {
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

	var ruleRef string
	isRegex := wrappers.BoolValue{Value: true}
	headers := make([]*envoy_api_v2_route.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: ":path", Value: h.Path, Regex: &isRegex})
		ruleRef = `PathRegexp("` + h.Path + `")`
	}
	if h.Method != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: ":method", Value: h.Method, Regex: &isRegex})
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `MethodRegexp("` + h.Method + `")`
	}

	if h.Host != "" {
		headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: ":authority", Value: h.Host, Regex: &isRegex})
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
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: key, Value: strs[1]})
			ruleRef += key + `","` + strs[1]
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_api_v2_route.HeaderMatcher{Name: strs[0]})
			ruleRef += strs[0]
		}
		ruleRef += `")`
	}

	// Envoy v2 API has a Path Regex, but it has not been
	// implemented yet, so we must always match the root of the
	// path to not miss anything.
	return &envoy_api_v2_route.Route{
		Match: &envoy_api_v2_route.RouteMatch{
			PathSpecifier: &envoy_api_v2_route.RouteMatch_Prefix{Prefix: "/"},
			Headers:       headers,
		},
		Action: envoyRouteAllowAction,
		Metadata: &envoy_api_v2_core.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				"envoy.router": {Fields: map[string]*structpb.Value{
					"cilium_rule_ref": {&structpb.Value_StringValue{StringValue: ruleRef}},
				}},
			},
		},
	}
}

func getRouteConfiguration(name string, l7rules policy.L7DataMap) *envoy_api_v2.RouteConfiguration {
	routes := make([]*envoy_api_v2_route.Route, 0, len(l7rules))
	for _, ep := range l7rules {
		// XXX: We should translate the fromEndpoints selector
		// (the key of the l7rules map) to a filter in Envoy
		// listener and not simply append the rules together.
		for _, h := range ep.HTTP {
			routes = append(routes, translatePolicyRule(h))
		}
	}
	return &envoy_api_v2.RouteConfiguration{
		Name: name,
		VirtualHosts: []*envoy_api_v2_route.VirtualHost{{
			Name:    name,
			Domains: []string{"*"},
			Routes:  routes,
		}},
	}
}

func createBootstrap(filePath string, name, cluster, version string, xdsSock, envoyClusterName string, adminPort uint32) {
	bs := &envoy_config_bootstrap_v2.Bootstrap{
		Node: &envoy_api_v2_core.Node{Id: name, Cluster: cluster, Metadata: nil, Locality: nil, BuildVersion: version},
		StaticResources: &envoy_config_bootstrap_v2.Bootstrap_StaticResources{
			Clusters: []*envoy_api_v2.Cluster{
				{
					Name:              envoyClusterName,
					Type:              envoy_api_v2.Cluster_ORIGINAL_DST,
					ConnectTimeout:    &duration.Duration{Seconds: 1, Nanos: 0},
					CleanupInterval:   &duration.Duration{Seconds: 1, Nanos: 500000000},
					LbPolicy:          envoy_api_v2.Cluster_ORIGINAL_DST_LB,
					ProtocolSelection: envoy_api_v2.Cluster_USE_CONFIGURED_PROTOCOL,
				},
				{
					Name:           "xdsCluster",
					Type:           envoy_api_v2.Cluster_STATIC,
					ConnectTimeout: &duration.Duration{Seconds: 1, Nanos: 0},
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
						ApiType:      envoy_api_v2_core.ApiConfigSource_GRPC,
						ClusterNames: []string{"xdsCluster"},
					},
				},
			},
		},
		Admin: &envoy_config_bootstrap_v2.Admin{
			AccessLogPath: "/dev/null",
			Address: &envoy_api_v2_core.Address{
				Address: &envoy_api_v2_core.Address_SocketAddress{
					SocketAddress: &envoy_api_v2_core.SocketAddress{
						Protocol:      envoy_api_v2_core.SocketAddress_TCP,
						Address:       "127.0.0.1",
						PortSpecifier: &envoy_api_v2_core.SocketAddress_PortValue{PortValue: adminPort},
					},
				},
			},
		},
	}

	log.Debug("Envoy: Bootstrap: ", bs.String())
	data, err := proto.Marshal(bs)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Marshaling bootstrap failed")
	}
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error writing Envoy bootstrap file")
	}
}
