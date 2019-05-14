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

var (
	_        = Suite(&ServerSuite{})
	IPv4Addr = "10.1.1.1"
	Identity = identity.NumericIdentity(123)
)

var PortRuleHTTP1 = &api.PortRuleHTTP{
	Path:    "/foo",
	Method:  "GET",
	Host:    "foo.cilium.io",
	Headers: []string{"header2 value", "header1"},
}

var PortRuleHTTP2 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "PUT",
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

var EndpointSelector1 = api.NewESFromLabels(
	labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
)

// EndpointSelector1 with FromRequires("k8s:version=v2") folded in
var RequiresV2Selector1 = api.NewESFromLabels(
	labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
	labels.NewLabel("version", "v2", labels.LabelSourceK8s),
)

var EndpointSelector2 = api.NewESFromLabels(
	labels.NewLabel("version", "v1", labels.LabelSourceK8s),
)

// Wildcard endpoint selector with FromRequires("k8s:version=v2") folded in
var RequiresV2Selector = api.NewESFromLabels(
	labels.NewLabel("version", "v2", labels.LabelSourceK8s),
)

var L7Rules1 = api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}}

var L7Rules2 = api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1}}

var IdentityCache = cache.IdentityCache{
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

var L4PolicyMap1 = map[string]policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			EndpointSelector1: L7Rules1,
		},
	},
}

var L4PolicyMap1RequiresV2 = map[string]policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			RequiresV2Selector1: L7Rules1,
		},
	},
}

var L4PolicyMap2 = map[string]policy.L4Filter{
	"8080/UDP": {
		Port:     8080,
		Protocol: api.ProtoUDP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			EndpointSelector2: L7Rules2,
		},
	},
}

var L4PolicyMap3 = map[string]policy.L4Filter{
	"80/UDP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			api.WildcardEndpointSelector: L7Rules1,
		},
	},
}

var L4PolicyMap3RequiresV2 = map[string]policy.L4Filter{
	"80/UDP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			RequiresV2Selector: L7Rules1,
		},
	},
}

// L4PolicyMap4 is an L4-only policy, with no L7 rules.
var L4PolicyMap4 = map[string]policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7RulesPerEp: policy.L7DataMap{
			EndpointSelector1: api.L7Rules{},
		},
	},
}

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5 = map[string]policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		L7RulesPerEp: policy.L7DataMap{
			api.WildcardEndpointSelector: api.L7Rules{},
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

var ExpectedPerPortPolicies2 = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_api_v2_core.SocketAddress_UDP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule2,
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
	obtained, _ := getHTTPRule(PortRuleHTTP1)
	c.Assert(obtained, checker.DeepEquals, ExpectedHeaders1)
}

func (s *ServerSuite) TestGetPortNetworkPolicyRule(c *C) {
	obtained := getPortNetworkPolicyRule(EndpointSelector1, policy.ParserTypeHTTP, L7Rules1,
		IdentityCache)
	c.Assert(obtained, checker.DeepEquals, ExpectedPortNetworkPolicyRule1)

	obtained = getPortNetworkPolicyRule(EndpointSelector2, policy.ParserTypeHTTP, L7Rules2,
		IdentityCache)
	c.Assert(obtained, checker.DeepEquals, ExpectedPortNetworkPolicyRule2)
}

func (s *ServerSuite) TestGetDirectionNetworkPolicy(c *C) {
	// L4+L7
	obtained := getDirectionNetworkPolicy(L4PolicyMap1, true, IdentityCache)
	c.Assert(obtained, checker.DeepEquals, ExpectedPerPortPolicies1)

	// L4+L7
	obtained = getDirectionNetworkPolicy(L4PolicyMap2, true, IdentityCache)
	c.Assert(obtained, checker.DeepEquals, ExpectedPerPortPolicies2)

	// L4-only
	obtained = getDirectionNetworkPolicy(L4PolicyMap4, true, IdentityCache)
	c.Assert(obtained, checker.DeepEquals, ExpectedPerPortPolicies6)

	// L4-only
	obtained = getDirectionNetworkPolicy(L4PolicyMap5, true, IdentityCache)
	c.Assert(obtained, checker.DeepEquals, ExpectedPerPortPolicies7)
}

func (s *ServerSuite) TestGetNetworkPolicy(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy1, true, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies1,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcard(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2, true, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies3,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyDeny(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy1RequiresV2, true, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies4RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcardDeny(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2RequiresV2, true, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies5RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyNil(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", nil, true, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  nil,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyIngressNotEnforced(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2, false, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: allowAllPortNetworkPolicy,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyEgressNotEnforced(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4Policy2RequiresV2, true, false, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies5RequiresV2,
		EgressPerPortPolicies:  allowAllPortNetworkPolicy,
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

var L4PolicyL7 = &policy.L4Policy{
	Ingress: map[string]policy.L4Filter{
		"9090/TCP": {
			Port: 9090, Protocol: api.ProtoTCP,
			L7Parser: "tester",
			L7RulesPerEp: policy.L7DataMap{
				EndpointSelector1: api.L7Rules{
					L7Proto: "tester",
					L7: []api.PortRuleL7{
						map[string]string{
							"method": "PUT",
							"path":   "/"},
						map[string]string{
							"method": "GET",
							"path":   "/"},
					},
				},
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
	obtained := getNetworkPolicy(IPv4Addr, Identity, "", L4PolicyL7, true, true, IdentityCache)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPoliciesL7,
	}
	// XXX: DeepEquals on maps?
	c.Assert(obtained, checker.DeepEquals, expected)
}
