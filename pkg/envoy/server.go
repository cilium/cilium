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
	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_listener "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/listener"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	envoy_config_bootstrap_v2 "github.com/cilium/cilium/pkg/envoy/envoy/config/bootstrap/v2"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"fmt"
	"github.com/gogo/protobuf/sortkeys"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spf13/viper"
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

	// loggers maps a listener resource name to its Logger.
	loggers map[string]Logger

	// listenerMutator publishes listener updates to Envoy proxies.
	listenerMutator xds.AckingResourceMutator

	// stopServer stops the xDS gRPC server.
	stopServer context.CancelFunc
}

func createXDSServer(path, accessLogPath string) *XDSServer {
	os.Remove(path)
	socketListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", path)
	}

	ldsCache := xds.NewCache()
	ldsMutator := xds.NewAckingResourceMutatorWrapper(ldsCache, xds.IstioNodeToIP)
	ldsConfig := &xds.ResourceTypeConfiguration{
		Source:      ldsCache,
		AckObserver: ldsMutator,
	}

	npdsConfig := &xds.ResourceTypeConfiguration{
		Source:      NetworkPolicyCache,
		AckObserver: AckingNetworkPolicyMutator,
	}

	nphdsConfig := &xds.ResourceTypeConfiguration{
		Source:      NetworkPolicyHostsCache,
		AckObserver: nil, // We don't wait for ACKs for those resources.
	}

	stopServer := StartXDSGRPCServer(socketListener, ldsConfig, npdsConfig, nphdsConfig, 5*time.Second)

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
								"api_config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
									"api_type":      {&structpb.Value_NumberValue{NumberValue: float64(envoy_api_v2_core.ApiConfigSource_GRPC)}},
									"cluster_names": {&structpb.Value_StringValue{StringValue: "xdsCluster"}},
								}}}},
							}}}},
						}}}},
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name":   {&structpb.Value_StringValue{StringValue: "envoy.router"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{}}}},
						}}}},
					}}}},
					"route_config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
						"virtual_hosts": {&structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
							{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"name": {&structpb.Value_StringValue{StringValue: "default_route"}},
								"domains": {&structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
									{&structpb.Value_StringValue{StringValue: "*"}},
								}}}},
								"routes": {&structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
									{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
										"match": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											"prefix": {&structpb.Value_StringValue{StringValue: "/"}},
										}}}},
										"route": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
											"cluster": {&structpb.Value_StringValue{StringValue: "cluster1"}},
										}}}},
									}}}},
								}}}},
							}}}},
						}}}},
					}}}},
				}},
			}},
		}},
		ListenerFilters: []*envoy_api_v2_listener.ListenerFilter{{
			Name: "cilium.bpf_metadata",
			Config: &structpb.Struct{Fields: map[string]*structpb.Value{
				"is_ingress": {&structpb.Value_BoolValue{BoolValue: false}},
				"bpf_root":   {&structpb.Value_StringValue{StringValue: "/sys/fs/bpf"}},
			}},
		}},
	}

	return &XDSServer{
		socketPath:      path,
		listenerProto:   listenerProto,
		loggers:         make(map[string]Logger),
		listenerMutator: ldsMutator,
		stopServer:      stopServer,
	}
}

func (s *XDSServer) addListener(name string, endpoint_policy_name string, port uint16, isIngress bool, logger Logger, wg *completion.WaitGroup) {
	log.Debug("Envoy: addListener ", name)

	s.mutex.Lock()

	// Bail out if this listener already exists
	if _, ok := s.loggers[name]; ok {
		log.Fatalf("Envoy: addListener: Listener %s already exists!", name)
	}

	s.loggers[name] = logger

	s.mutex.Unlock()

	// Fill in the listener-specific parts.
	listenerConf := proto.Clone(s.listenerProto).(*envoy_api_v2.Listener)
	listenerConf.Name = name
	listenerConf.Address.GetSocketAddress().PortSpecifier = &envoy_api_v2_core.SocketAddress_PortValue{PortValue: uint32(port)}
	if isIngress {
		listenerConf.ListenerFilters[0].Config.Fields["is_ingress"].GetKind().(*structpb.Value_BoolValue).BoolValue = true
	}

	listenerConf.FilterChains[0].Filters[0].Config.Fields["http_filters"].GetListValue().Values[0].GetStructValue().Fields["config"].GetStructValue().Fields["listener_id"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: name}}
	listenerConf.FilterChains[0].Filters[0].Config.Fields["http_filters"].GetListValue().Values[0].GetStructValue().Fields["config"].GetStructValue().Fields["policy_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: endpoint_policy_name}}

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg.AddCompletion())
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

	isRegex := wrappers.BoolValue{Value: true}
	headers = make([]*envoy_api_v2_route.HeaderMatcher, 0, cnt)
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
	SortHeaderMatchers(headers)
	return
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
					ProtocolSelection: envoy_api_v2.Cluster_USE_DOWNSTREAM_PROTOCOL,
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

func getPortNetworkPolicyRule(sel api.EndpointSelector, l7Parser policy.L7ParserType, l7Rules api.L7Rules,
	labelsMap identity.IdentityCache, deniedIdentities map[identity.NumericIdentity]bool) *cilium.PortNetworkPolicyRule {
	// In case the endpoint selector is a wildcard and there are no denied
	// identities, optimize the policy by setting an empty remote policies list
	// to match all remote policies.
	var remotePolicies []uint64
	if !sel.IsWildcard() || len(deniedIdentities) > 0 {
		for id, labels := range labelsMap {
			if !deniedIdentities[id] && sel.Matches(labels) {
				remotePolicies = append(remotePolicies, uint64(id))
			}
		}

		// No remote policies would match this rule. Discard it.
		if len(remotePolicies) == 0 {
			return nil
		}

		sortkeys.Uint64s(remotePolicies)
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
			r.L7Rules = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: &cilium.HttpNetworkPolicyRules{
					HttpRules: httpRules,
				},
			}
		}
	default:
		// No L7 parser means nothing for an L7 proxy to do. Ignore the rule.
		return nil
	}
	// TODO: Support Kafka.

	return r
}

func getDirectionNetworkPolicy(l4Policy policy.L4PolicyMap, labelsMap identity.IdentityCache, deniedIdentities map[identity.NumericIdentity]bool) []*cilium.PortNetworkPolicy {
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

		for sel, l7 := range l4.L7RulesPerEp {
			rule := getPortNetworkPolicyRule(sel, l4.L7Parser, l7, labelsMap, deniedIdentities)
			if rule != nil {
				pnp.Rules = append(pnp.Rules, rule)
			}
		}
		SortPortNetworkPolicyRules(pnp.Rules)

		PerPortPolicies = append(PerPortPolicies, pnp)
	}

	SortPortNetworkPolicies(PerPortPolicies)

	return PerPortPolicies
}

// getNetworkPolicy converts a network policy into a cilium.NetworkPolicy.
func getNetworkPolicy(name string, id identity.NumericIdentity, policy *policy.L4Policy,
	labelsMap identity.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool) *cilium.NetworkPolicy {
	return &cilium.NetworkPolicy{
		Name:                   name,
		Policy:                 uint64(id),
		IngressPerPortPolicies: getDirectionNetworkPolicy(policy.Ingress, labelsMap, deniedIngressIdentities),
		EgressPerPortPolicies:  getDirectionNetworkPolicy(policy.Egress, labelsMap, deniedEgressIdentities),
	}
}

// UpdateNetworkPolicy adds or updates a network policy in the set of published
// to L7 proxies.
// When the proxy acknowledges the network policy update, it will result in
// a subsequent call to the endpoint's OnProxyPolicyAcknowledge() function.
func UpdateNetworkPolicy(ep NetworkPolicyEndpoint, policy *policy.L4Policy,
	labelsMap identity.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool, wg *completion.WaitGroup) error {

	// First, validate all policies
	ips := []string{
		ep.GetIPv6Address(),
		ep.GetIPv4Address(),
	}
	policies := []*cilium.NetworkPolicy{}
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		networkPolicy := getNetworkPolicy(ip, ep.GetIdentity(), policy, labelsMap, deniedIngressIdentities, deniedEgressIdentities)
		err := networkPolicy.Validate()
		if err != nil {
			return fmt.Errorf("error validating generated NetworkPolicy for %s: %s", ip, err)
		}
		policies = append(policies, networkPolicy)
	}

	// When successful, push them into the cache.
	for _, p := range policies {
		policyRevision := policy.Revision
		callback := func() {
			go ep.OnProxyPolicyUpdate(policyRevision)
		}
		var c *completion.Completion
		if wg == nil {
			c = completion.NewCallback(context.Background(), callback)
		} else {
			c = wg.AddCompletionWithCallback(callback)
		}
		nodeIDs := make([]string, 0, 1)
		if viper.GetBool("sidecar-http-proxy") {
			if ep.GetIPv4Address() == "" {
				log.Fatal("envoy: sidecar proxy has no IPv4 address")
			}
			nodeIDs = append(nodeIDs, ep.GetIPv4Address())
		} else {
			nodeIDs = append(nodeIDs, "127.0.0.1")
		}
		AckingNetworkPolicyMutator.Upsert(NetworkPolicyTypeURL, p.Name, p, nodeIDs, c)
	}
	return nil
}

// RemoveNetworkPolicy removes network policies relevant to the specified
// endpoint from the set published to L7 proxies, and stops listening for
// acks for policies on this endpoint.
func RemoveNetworkPolicy(ep NetworkPolicyEndpoint) {
	if ep.GetIPv6Address() != "" {
		NetworkPolicyCache.Delete(NetworkPolicyTypeURL, ep.GetIPv6Address(), false)
	}
	if ep.GetIPv4Address() != "" {
		NetworkPolicyCache.Delete(NetworkPolicyTypeURL, ep.GetIPv4Address(), false)
	}
}
