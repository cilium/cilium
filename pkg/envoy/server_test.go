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

	"github.com/cilium/proxy/go/cilium/api"
	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/proxy/go/envoy/api/v2/route"
	. "gopkg.in/check.v1"
)

type ServerSuite struct{}

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, selections, added, deleted []identity.NumericIdentity) {
}

var (
	_        = Suite(&ServerSuite{})
	IPv4Addr = "10.1.1.1"
	Identity = identity.NumericIdentity(123)
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

var ExpectedHeaders1 = []*envoy_api_v2_route.HeaderMatcher{
	{
		Name:                 ":authority",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "foo.cilium.io"},
	},
	{
		Name:                 ":method",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "GET"},
	},
	{
		Name:                 ":path",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "/foo"},
	},
	{
		Name:                 "header1",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_PresentMatch{PresentMatch: true},
	},
	{
		Name:                 "header2",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: "value"},
	},
}

var ExpectedHeaders2 = []*envoy_api_v2_route.HeaderMatcher{
	{
		Name:                 ":method",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "PUT"},
	},
	{
		Name:                 ":path",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "/bar"},
	},
}

var ExpectedHeaderMatches2 = []*cilium.HeaderMatch{
	{
		MismatchAction: cilium.HeaderMatch_REPLACE_ON_MISMATCH,
		Name:           "user-agent",
		Value:          "dummy-agent",
	},
}

var ExpectedHeaders3 = []*envoy_api_v2_route.HeaderMatcher{
	{
		Name:                 ":method",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "GET"},
	},
	{
		Name:                 ":path",
		HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "/bar"},
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

	// Wildcard endpoint selector with FromRequires("k8s:version=v2") folded in
	RequiresV2Selector = api.NewESFromLabels(
		labels.NewLabel("version", "v2", labels.LabelSourceK8s),
	)
	cachedRequiresV2Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, RequiresV2Selector)
)

var L7Rules1 = &policy.PerEpData{L7Rules: api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}}}

var L7Rules1HeaderMatch = &policy.PerEpData{L7Rules: api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2HeaderMatch}}}

var L7Rules2 = &policy.PerEpData{L7Rules: api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1}}}

var ExpectedPortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1002},
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule1HeaderMatch = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1002},
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2, HeaderMatches: ExpectedHeaderMatches2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule2 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1003},
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule3 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil, // Wildcard. Select all.
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule4RequiresV2 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1002}, // Like ExpectedPortNetworkPolicyRule1 but "k8s:version=v2" is required.
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule5RequiresV2 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1002}, // Wildcard, but "k8s:version=v2" required
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule6 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1002},
}

var L4PolicyMap1 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			cachedSelector1: L7Rules1,
		},
	},
}

var L4PolicyMap1HeaderMatch = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			cachedSelector1: L7Rules1HeaderMatch,
		},
	},
}

var L4PolicyMap1RequiresV2 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			cachedRequiresV2Selector1: L7Rules1,
		},
	},
}

var L4PolicyMap2 = map[string]*policy.L4Filter{
	"8080/UDP": {
		Port:     8080,
		Protocol: api.ProtoUDP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			cachedSelector2: L7Rules2,
		},
	},
}

var L4PolicyMap3 = map[string]*policy.L4Filter{
	"80/UDP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			wildcardCachedSelector: L7Rules1,
		},
	},
}

var L4PolicyMap3RequiresV2 = map[string]*policy.L4Filter{
	"80/UDP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			cachedRequiresV2Selector: L7Rules1,
		},
	},
}

// L4PolicyMap4 is an L4-only policy, with no L7 rules.
var L4PolicyMap4 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7RulesPerEp: policy.L7DataMap{
			cachedSelector1: &policy.PerEpData{L7Rules: api.L7Rules{}},
		},
	},
}

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5 = map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7RulesPerEp: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerEpData{L7Rules: api.L7Rules{}},
		},
	},
}

var ExpectedPerPortPolicies1 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1,
		},
	},
}

var ExpectedPerPortPolicies1HeaderMatch = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1HeaderMatch,
		},
	},
}

var ExpectedPerPortPolicies3 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule3,
		},
	},
}

var ExpectedPerPortPolicies4RequiresV2 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule4RequiresV2,
		},
	},
}

var ExpectedPerPortPolicies5RequiresV2 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule5RequiresV2,
		},
	},
}

var ExpectedPerPortPolicies6 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule6,
		},
	},
}

var ExpectedPerPortPolicies7 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
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

var L4Policy2RequiresV2 = &policy.L4Policy{
	Ingress: L4PolicyMap3RequiresV2,
	Egress:  L4PolicyMap2,
}

func (s *ServerSuite) TestGetHTTPRule(c *C) {
	obtained, canShortCircuit := getHTTPRule(nil, PortRuleHTTP1, "")
	c.Assert(obtained.Headers, checker.Equals, ExpectedHeaders1)
	c.Assert(canShortCircuit, checker.Equals, true)
}

func (s *ServerSuite) TestGetPortNetworkPolicyRule(c *C) {
	obtained, canShortCircuit := getPortNetworkPolicyRule(cachedSelector1, policy.ParserTypeHTTP, L7Rules1)
	c.Assert(obtained, checker.Equals, ExpectedPortNetworkPolicyRule1)
	c.Assert(canShortCircuit, checker.Equals, true)

	obtained, canShortCircuit = getPortNetworkPolicyRule(cachedSelector1, policy.ParserTypeHTTP, L7Rules1HeaderMatch)
	c.Assert(obtained, checker.Equals, ExpectedPortNetworkPolicyRule1HeaderMatch)
	c.Assert(canShortCircuit, checker.Equals, false)

	obtained, canShortCircuit = getPortNetworkPolicyRule(cachedSelector2, policy.ParserTypeHTTP, L7Rules2)
	c.Assert(obtained, checker.Equals, ExpectedPortNetworkPolicyRule2)
	c.Assert(canShortCircuit, checker.Equals, true)
}

func (s *ServerSuite) TestGetDirectionNetworkPolicy(c *C) {
	// L4+L7
	obtained := getDirectionNetworkPolicy(L4PolicyMap1)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies1)

	// L4+L7 with header mods
	obtained = getDirectionNetworkPolicy(L4PolicyMap1HeaderMatch)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies1HeaderMatch)

	// L4+L7 for an unsupported protocol (UDP)
	obtained = getDirectionNetworkPolicy(L4PolicyMap2)
	c.Assert(obtained, checker.Equals, []*cilium.PortNetworkPolicy(nil))

	// L4-only
	obtained = getDirectionNetworkPolicy(L4PolicyMap4)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies6)

	// L4-only
	obtained = getDirectionNetworkPolicy(L4PolicyMap5)
	c.Assert(obtained, checker.Equals, ExpectedPerPortPolicies7)
}

func (s *ServerSuite) TestGetNetworkPolicy(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy1, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies1,
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcard(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies3,
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyDeny(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy1RequiresV2, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies4RequiresV2,
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcardDeny(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2RequiresV2, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies5RequiresV2,
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyNil(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", nil, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  nil,
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyIngressNotEnforced(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2, false, true)
	expected := &cilium.NetworkPolicy{
		Name:   IPv4Addr,
		Policy: uint64(Identity),
	}
	c.Assert(obtained, checker.Equals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyEgressNotEnforced(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2RequiresV2, true, false)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies5RequiresV2,
	}
	c.Assert(obtained, checker.Equals, expected)
}

var L4PolicyL7 = &policy.L4Policy{
	Ingress: map[string]*policy.L4Filter{
		"9090/TCP": {
			Port: 9090, Protocol: api.ProtoTCP,
			L7Parser: "tester",
			L7RulesPerEp: policy.L7DataMap{
				cachedSelector1: &policy.PerEpData{L7Rules: api.L7Rules{
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
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			RemotePolicies: []uint64{1001, 1002},
			L7Proto:        "tester",
			L7: &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: &cilium.L7NetworkPolicyRules{
					L7Rules: []*cilium.L7NetworkPolicyRule{
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
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4PolicyL7, true, true)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPoliciesL7,
	}
	c.Assert(obtained, checker.Equals, expected)
}
