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

// +build !privileged_tests

package envoy

import (
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/api/kafka"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/proxy/logger/test"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher "github.com/cilium/proxy/go/envoy/type/matcher/v3"

	. "gopkg.in/check.v1"
)

type ServerSuite struct{}

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, added, deleted []identity.NumericIdentity) {
}

var (
	_        = Suite(&ServerSuite{})
	IPv4Addr = "10.1.1.1"
	Identity = identity.NumericIdentity(123)

	ep logger.EndpointUpdater = &test.ProxyUpdaterMock{
		Id:       1000,
		Ipv4:     "10.0.0.1",
		Ipv6:     "f00d::1",
		Labels:   []string{"id.foo", "id.bar"},
		Identity: Identity,
	}
)

var PortRuleHTTP1 = &api.PortRuleHTTP{
	Path:    "/foo",
	Method:  "GET",
	Host:    "foo.cilium.io",
	Headers: []string{"header2: value", "header1"},
}

var PortRuleHTTP2 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "PUT",
}

var PortRuleHTTP2HeaderMatch = &api.PortRuleHTTP{
	Path:          "/bar",
	Method:        "PUT",
	HeaderMatches: []*api.HeaderMatch{{Mismatch: api.MismatchActionReplace, Name: "user-agent", Value: "dummy-agent"}},
}

var PortRuleHTTP3 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "GET",
}

var googleRe2 = &envoy_type_matcher.RegexMatcher_GoogleRe2{GoogleRe2: &envoy_type_matcher.RegexMatcher_GoogleRE2{}}

var ExpectedHeaders1 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":authority",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "foo.cilium.io",
			}},
	},
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "GET",
			}},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "/foo",
			}},
	},
	{
		Name:                 "header1",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
	},
	{
		Name:                 "header2",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_ExactMatch{ExactMatch: "value"},
	},
}

var ExpectedHeaders2 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "PUT",
			}},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "/bar",
			}},
	},
}

var ExpectedHeaderMatches2 = []*cilium.HeaderMatch{
	{
		MismatchAction: cilium.HeaderMatch_REPLACE_ON_MISMATCH,
		Name:           "user-agent",
		Value:          "dummy-agent",
	},
}

var ExpectedHeaders3 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "GET",
			}},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &envoy_type_matcher.RegexMatcher{
				EngineType: googleRe2,
				Regex:      "/bar",
			}},
	},
}

var (
	dummySelectorCacheUser = &DummySelectorCacheUser{}

	IdentityCache = cache.IdentityCache{
		1001: labels.LabelArray{
			labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
			labels.NewLabel("version", "v1", labels.LabelSourceK8s),
		},
		1002: labels.LabelArray{
			labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
			labels.NewLabel("version", "v2", labels.LabelSourceK8s),
		},
		1003: labels.LabelArray{
			labels.NewLabel("app", "cassandra", labels.LabelSourceK8s),
			labels.NewLabel("version", "v1", labels.LabelSourceK8s),
		},
	}

	testSelectorCache = policy.NewSelectorCache(IdentityCache)

	wildcardCachedSelector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, api.WildcardEndpointSelector)

	EndpointSelector1 = api.NewESFromLabels(
		labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
	)
	cachedSelector1, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, EndpointSelector1)

	// EndpointSelector1 with FromRequires("k8s:version=v2") folded in
	RequiresV2Selector1 = api.NewESFromLabels(
		labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
		labels.NewLabel("version", "v2", labels.LabelSourceK8s),
	)
	cachedRequiresV2Selector1, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, RequiresV2Selector1)

	EndpointSelector2 = api.NewESFromLabels(
		labels.NewLabel("version", "v1", labels.LabelSourceK8s),
	)
	cachedSelector2, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, EndpointSelector2)
)

var L7Rules12 = &policy.PerSelectorPolicy{L7Rules: api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}}}

var L7Rules12HeaderMatch = &policy.PerSelectorPolicy{L7Rules: api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2HeaderMatch}}}

var L7Rules1 = &policy.PerSelectorPolicy{L7Rules: api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1}}}

var ExpectedHttpRule1 = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedHttpRule12 = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders2},
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedHttpRule122HeaderMatch = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders2, HeaderMatches: ExpectedHeaderMatches2},
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedPortNetworkPolicyRule12 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1002},
	L7:             ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule12Wildcard = &cilium.PortNetworkPolicyRule{
	L7: ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule122HeaderMatch = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1002},
	L7:             ExpectedHttpRule122HeaderMatch,
}

var ExpectedPortNetworkPolicyRule122HeaderMatchWildcard = &cilium.PortNetworkPolicyRule{
	L7: ExpectedHttpRule122HeaderMatch,
}

var ExpectedPortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1003},
	L7:             ExpectedHttpRule1,
}

var ExpectedPortNetworkPolicyRule1Wildcard = &cilium.PortNetworkPolicyRule{
	L7: ExpectedHttpRule1,
}

var L4PolicyMap1 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerSelector: policy.L7DataMap{
			cachedSelector1: L7Rules12,
		},
	},
}

var L4PolicyMap1HeaderMatch = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerSelector: policy.L7DataMap{
			cachedSelector1: L7Rules12HeaderMatch,
		},
	},
}

var L4PolicyMap1RequiresV2 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerSelector: policy.L7DataMap{
			cachedSelector1:           L7Rules1,
			cachedRequiresV2Selector1: L7Rules12,
		},
	},
}

var L4PolicyMap2 = map[string]*policy.L4Filter{
	"8080/TCP": {
		Port:     8080,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerSelector: policy.L7DataMap{
			cachedSelector2: L7Rules1,
		},
	},
}

var L4PolicyMap3 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerSelector: policy.L7DataMap{
			wildcardCachedSelector: L7Rules12,
		},
	},
}

// L4PolicyMap4 is an L4-only policy, with no L7 rules.
var L4PolicyMap4 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7RulesPerSelector: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{}},
		},
	},
}

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7RulesPerSelector: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{}},
		},
	},
}

var ExpectedPerPortPolicies1Wildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1Wildcard,
		},
	},
}

var ExpectedPerPortPolicies122HeaderMatchWildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule122HeaderMatchWildcard,
		},
	},
}

var ExpectedPerPortPolicies12Wildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12Wildcard,
		},
	},
}

var ExpectedPerPortPolicies12RequiresV2 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			RemotePolicies: []uint64{1001, 1002},
			L7:             ExpectedHttpRule1,
		}, {
			RemotePolicies: []uint64{1002},
			L7:             ExpectedHttpRule12,
		}},
	},
}

var ExpectedPerPortPoliciesWildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
	},
}

var L4Policy1 = &policy.L4Policy{
	Ingress: L4PolicyMap1,
	Egress:  L4PolicyMap2,
}

var L4Policy1RequiresV2 = &policy.L4Policy{
	Ingress: L4PolicyMap1RequiresV2,
	Egress:  L4PolicyMap2,
}

var L4Policy2 = &policy.L4Policy{
	Ingress: L4PolicyMap3,
	Egress:  L4PolicyMap2,
}

func (s *ServerSuite) TestGetHTTPRule(c *C) {
	obtained, canShortCircuit := getHTTPRule(nil, PortRuleHTTP1, "")
	c.Assert(obtained.Headers, checker.Equals, ExpectedHeaders1)
	c.Assert(canShortCircuit, checker.Equals, true)
}

func (s *ServerSuite) TestGetPortNetworkPolicyRule(c *C) {
	obtained, canShortCircuit := getPortNetworkPolicyRule(cachedSelector1, cachedSelector1.IsWildcard(), policy.ParserTypeHTTP, L7Rules12)
	c.Assert(obtained, checker.Equals, ExpectedPortNetworkPolicyRule12)
	c.Assert(canShortCircuit, checker.Equals, true)

	obtained, canShortCircuit = getPortNetworkPolicyRule(cachedSelector1, cachedSelector1.IsWildcard(), policy.ParserTypeHTTP, L7Rules12HeaderMatch)
	c.Assert(obtained, checker.Equals, ExpectedPortNetworkPolicyRule122HeaderMatch)
	c.Assert(canShortCircuit, checker.Equals, false)

	obtained, canShortCircuit = getPortNetworkPolicyRule(cachedSelector2, cachedSelector2.IsWildcard(), policy.ParserTypeHTTP, L7Rules1)
	c.Assert(obtained, checker.Equals, ExpectedPortNetworkPolicyRule1)
	c.Assert(canShortCircuit, checker.Equals, true)
}

func (s *ServerSuite) TestGetDirectionNetworkPolicy(c *C) {
	// L4+L7
	obtained := getDirectionNetworkPolicy(ep, L4PolicyMap1, true)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies12Wildcard)

	// L4+L7 with header mods
	obtained = getDirectionNetworkPolicy(ep, L4PolicyMap1HeaderMatch, true)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies122HeaderMatchWildcard)

	// L4+L7
	obtained = getDirectionNetworkPolicy(ep, L4PolicyMap2, true)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies1Wildcard)

	// L4-only
	obtained = getDirectionNetworkPolicy(ep, L4PolicyMap4, true)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPoliciesWildcard)

	// L4-only
	obtained = getDirectionNetworkPolicy(ep, L4PolicyMap5, true)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPoliciesWildcard)
}

func (s *ServerSuite) TestGetNetworkPolicy(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4Policy1, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies12Wildcard,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1Wildcard,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcard(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4Policy2, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies12Wildcard,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1Wildcard,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyDeny(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4Policy1RequiresV2, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1Wildcard,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcardDeny(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4Policy1RequiresV2, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1Wildcard,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyNil(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, nil, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  nil,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyIngressNotEnforced(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4Policy2, false, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: allowAllPortNetworkPolicy,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1Wildcard,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyEgressNotEnforced(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4Policy1RequiresV2, true, false)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  allowAllPortNetworkPolicy,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

var L4PolicyL7 = &policy.L4Policy{
	Ingress: map[string]*policy.L4Filter{
		"9090/TCP": {
			Port: 9090, Protocol: api.ProtoTCP,
			L7Parser: "tester",
			L7RulesPerSelector: policy.L7DataMap{
				cachedSelector1: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{
					L7Proto: "tester",
					L7: []api.PortRuleL7{
						map[string]string{
							"method": "PUT",
							"path":   "/"},
						map[string]string{
							"method": "GET",
							"path":   "/"},
					},
				}},
			},
			Ingress: true,
		},
	},
}

var ExpectedPerPortPoliciesL7 = []*cilium.PortNetworkPolicy{
	{
		Port:     9090,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			// RemotePolicies: []uint64{1001, 1002}, // Effective wildcard due to only one selector in the policy
			L7Proto: "tester",
			L7: &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: &cilium.L7NetworkPolicyRules{
					L7AllowRules: []*cilium.L7NetworkPolicyRule{
						{Rule: map[string]string{
							"method": "PUT",
							"path":   "/"}},
						{Rule: map[string]string{
							"method": "GET",
							"path":   "/"}},
					},
				},
			}},
		},
	},
}

func (s *ServerSuite) TestGetNetworkPolicyL7(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4PolicyL7, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPoliciesL7,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

var L4PolicyKafka = &policy.L4Policy{
	Ingress: map[string]*policy.L4Filter{
		"9090/TCP": {
			Port: 9092, Protocol: api.ProtoTCP,
			L7Parser: "kafka",
			L7RulesPerSelector: policy.L7DataMap{
				cachedSelector1: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{
					Kafka: []kafka.PortRule{{
						Role:  "consume",
						Topic: "deathstar-plans",
					}},
				}},
			},
			Ingress: true,
		},
	},
}

var ExpectedPerPortPoliciesKafka = []*cilium.PortNetworkPolicy{
	{
		Port:     9092,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			// RemotePolicies: []uint64{1001, 1002}, // Effective wildcard due to only one selector in the policy
			L7Proto: "kafka",
			L7: &cilium.PortNetworkPolicyRule_KafkaRules{
				KafkaRules: &cilium.KafkaNetworkPolicyRules{
					KafkaRules: []*cilium.KafkaNetworkPolicyRule{{
						ApiVersion: -1,
						ApiKeys: []int32{int32(kafka.FetchKey), int32(kafka.OffsetsKey),
							int32(kafka.MetadataKey), int32(kafka.OffsetCommitKey),
							int32(kafka.OffsetFetchKey), int32(kafka.FindCoordinatorKey),
							int32(kafka.JoinGroupKey), int32(kafka.HeartbeatKey),
							int32(kafka.LeaveGroupKey), int32(kafka.SyncgroupKey),
							int32(kafka.APIVersionsKey)},
						ClientId: "",
						Topic:    "deathstar-plans",
					}},
				},
			}},
		},
	},
}

func (s *ServerSuite) TestGetNetworkPolicyKafka(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4PolicyKafka, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPoliciesKafka,
		ConntrackMapName:       "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}

var L4PolicyMySQL = &policy.L4Policy{
	Egress: map[string]*policy.L4Filter{
		"3306/TCP": {
			Port: 3306, Protocol: api.ProtoTCP,
			L7Parser: "envoy.filters.network.mysql_proxy",
			L7RulesPerSelector: policy.L7DataMap{
				cachedSelector1: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{
					L7Proto: "envoy.filters.network.mysql_proxy",
					L7: []api.PortRuleL7{
						map[string]string{
							"action":     "deny",
							"user.mysql": "select"},
					},
				}},
			},
			Ingress: false,
		},
	},
}

var ExpectedPerPortPoliciesMySQL = []*cilium.PortNetworkPolicy{
	{
		Port:     3306,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			// RemotePolicies: []uint64{1001, 1002}, // Effective wildcard due to only one selector in the policy
			L7Proto: "envoy.filters.network.mysql_proxy",
			L7: &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: &cilium.L7NetworkPolicyRules{
					L7DenyRules: []*cilium.L7NetworkPolicyRule{{
						MetadataRule: []*envoy_type_matcher.MetadataMatcher{{
							Filter: "envoy.filters.network.mysql_proxy",
							Path: []*envoy_type_matcher.MetadataMatcher_PathSegment{{
								Segment: &envoy_type_matcher.MetadataMatcher_PathSegment_Key{Key: "user.mysql"},
							}},
							Value: &envoy_type_matcher.ValueMatcher{
								MatchPattern: &envoy_type_matcher.ValueMatcher_ListMatch{
									ListMatch: &envoy_type_matcher.ListMatcher{
										MatchPattern: &envoy_type_matcher.ListMatcher_OneOf{
											OneOf: &envoy_type_matcher.ValueMatcher{
												MatchPattern: &envoy_type_matcher.ValueMatcher_StringMatch{
													StringMatch: &envoy_type_matcher.StringMatcher{
														MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
															Exact: "select",
														},
													},
												},
											},
										},
									},
								},
							},
						}},
					}},
				},
			}},
		},
	},
}

func (s *ServerSuite) TestGetNetworkPolicyMySQL(c *C) {
	obtained := getNetworkPolicy(ep, IPv4Addr, L4PolicyMySQL, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                  IPv4Addr,
		Policy:                uint64(Identity),
		EgressPerPortPolicies: ExpectedPerPortPoliciesMySQL,
		ConntrackMapName:      "global",
	}
	c.Assert(obtained, checker.Equals, expected)
}
