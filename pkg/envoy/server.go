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
	"github.com/cilium/cilium/pkg/policy/api/v2"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/gogo/protobuf/sortkeys"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spf13/viper"
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

// XDSServer provides a high-lever interface to manage resources published
// using the xDS gRPC API.
type XDSServer struct {
	// socketPath is the path to the gRPC UNIX domain socket.
	socketPath string

	// mutex protects accesses to the configuration resources.
	mutex lock.RWMutex

	// listenerProto is a generic Envoy Listener protobuf. Immutable.
	listenerProto *envoy_api_v2.Listener

	// listenerMutator publishes listener updates to Envoy proxies.
	listenerMutator xds.AckingResourceMutator

	// listeners is the set of names of listeners that have been added by
	// calling AddListener.
	// mutex must be held when accessing this.
	listeners map[string]struct{}

	// networkPolicyCache publishes network policy configuration updates to
	// Envoy proxies.
	networkPolicyCache *xds.Cache

	// networkPolicyMutator wraps networkPolicyCache to publish route
	// configuration updates to Envoy proxies.
	networkPolicyMutator xds.AckingResourceMutator

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
		FilterChains: []*envoy_api_v2_listener.FilterChain{{
			Filters: []*envoy_api_v2_listener.Filter{{
				Name: "cilium.network",
			}, {
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
		socketPath:             xdsPath,
		listenerProto:          listenerProto,
		listenerMutator:        ldsMutator,
		listeners:              make(map[string]struct{}),
		networkPolicyCache:     npdsCache,
		networkPolicyMutator:   npdsMutator,
		networkPolicyEndpoints: make(map[string]logger.EndpointUpdater),
		stopServer:             stopServer,
	}
}

// AddListener adds a listener to a running Envoy proxy.
func (s *XDSServer) AddListener(name string, endpointPolicyName string, port uint16, isIngress bool, wg *completion.WaitGroup) {
	log.Debugf("Envoy: addListener %s", name)

	s.mutex.Lock()

	// Bail out if this listener already exists
	if _, ok := s.listeners[name]; ok {
		log.Fatalf("Envoy: Attempt to add existing listener: %s", name)
	}
	s.listeners[name] = struct{}{}

	s.mutex.Unlock()

	// Fill in the listener-specific parts.
	listenerConf := proto.Clone(s.listenerProto).(*envoy_api_v2.Listener)
	listenerConf.Name = name
	listenerConf.Address.GetSocketAddress().PortSpecifier = &envoy_api_v2_core.SocketAddress_PortValue{PortValue: uint32(port)}
	if isIngress {
		listenerConf.ListenerFilters[0].Config.Fields["is_ingress"].GetKind().(*structpb.Value_BoolValue).BoolValue = true
	}

	listenerConf.FilterChains[0].Filters[1].Config.Fields["http_filters"].GetListValue().Values[0].GetStructValue().Fields["config"].GetStructValue().Fields["policy_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: endpointPolicyName}}

	s.listenerMutator.Upsert(ListenerTypeURL, name, listenerConf, []string{"127.0.0.1"}, wg.AddCompletion())
}

// RemoveListener removes an existing Envoy Listener.
func (s *XDSServer) RemoveListener(name string, wg *completion.WaitGroup) {
	s.mutex.Lock()
	log.Debugf("Envoy: removeListener %s", name)
	if _, ok := s.listeners[name]; !ok {
		// Bail out if this listener does not exist
		log.Fatalf("Envoy: Attempt to remove non-existent listener: %s", name)
	}
	delete(s.listeners, name)
	s.mutex.Unlock()

	s.listenerMutator.Delete(ListenerTypeURL, name, []string{"127.0.0.1"}, wg.AddCompletion())
}

func (s *XDSServer) stop() {
	s.stopServer()
	os.Remove(s.socketPath)
}

func getHTTPRule(h *v2.PortRuleHTTP) (headers []*envoy_api_v2_route.HeaderMatcher, ruleRef string) {
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

func getPortNetworkPolicyRule(sel v2.EndpointSelector, l7Parser policy.L7ParserType, l7Rules v2.L7Rules,
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

func getDirectionNetworkPolicy(l4Policy policy.L4PolicyMap, policyEnforced bool,
	labelsMap identity.IdentityCache, deniedIdentities map[identity.NumericIdentity]bool) []*cilium.PortNetworkPolicy {
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
		case v2.ProtoTCP:
			protocol = envoy_api_v2_core.SocketAddress_TCP
		case v2.ProtoUDP:
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
	ingressPolicyEnforced, egressPolicyEnforced bool, labelsMap identity.IdentityCache,
	deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool) *cilium.NetworkPolicy {
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
// a subsequent call to the endpoint's OnProxyPolicyAcknowledge() function.
func (s *XDSServer) UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced bool, labelsMap identity.IdentityCache,
	deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool, wg *completion.WaitGroup) error {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If there are no listeners configured, the local node's Envoy proxy won't
	// query for network policies and therefore will never ACK them, and we'd
	// wait forever.
	if !viper.GetBool("sidecar-http-proxy") && len(s.listeners) == 0 {
		wg = nil
	}

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
			return fmt.Errorf("error validating generated NetworkPolicy for %s: %s", ip, err)
		}
		policies = append(policies, networkPolicy)
	}

	// When successful, push them into the cache.
	for _, p := range policies {
		var callback func()
		if policy != nil {
			policyRevision := policy.Revision
			callback = func() {
				go ep.OnProxyPolicyUpdate(policyRevision)
			}
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
				log.Fatal("Envoy: Sidecar proxy has no IPv4 address")
			}
			nodeIDs = append(nodeIDs, ep.GetIPv4Address())
		} else {
			nodeIDs = append(nodeIDs, "127.0.0.1")
		}
		s.networkPolicyMutator.Upsert(NetworkPolicyTypeURL, p.Name, p, nodeIDs, c)
		s.networkPolicyEndpoints[p.Name] = ep
	}

	return nil
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
	resources, err := s.networkPolicyCache.GetResources(context.Background(), NetworkPolicyTypeURL, nil, nil, resourceNames)
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
