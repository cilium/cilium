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
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api/v3"

	"github.com/golang/protobuf/ptypes/wrappers"

	. "gopkg.in/check.v1"
)

type ServerSuite struct{}

var (
	_        = Suite(&ServerSuite{})
	IPv4Addr = "10.1.1.1"
	Identity = identity.NumericIdentity(123)
)

var PortRuleHTTP1 = &v3.PortRuleHTTP{
	Path:    "/foo",
	Method:  "GET",
	Host:    "foo.cilium.io",
	Headers: []string{"header2 value", "header1"},
}

var PortRuleHTTP2 = &v3.PortRuleHTTP{
	Path:   "/bar",
	Method: "PUT",
}

var PortRuleHTTP3 = &v3.PortRuleHTTP{
	Path:   "/bar",
	Method: "GET",
}

var ExpectedHeaders1 = []*envoy_api_v2_route.HeaderMatcher{
	{
		Name:  ":authority",
		Value: "foo.cilium.io",
		Regex: &wrappers.BoolValue{Value: true},
	},
	{
		Name:  ":method",
		Value: "GET",
		Regex: &wrappers.BoolValue{Value: true},
	},
	{
		Name:  ":path",
		Value: "/foo",
		Regex: &wrappers.BoolValue{Value: true},
	},
	{
		Name: "header1",
	},
	{
		Name:  "header2",
		Value: "value",
	},
}

var ExpectedHeaders2 = []*envoy_api_v2_route.HeaderMatcher{
	{
		Name:  ":method",
		Value: "PUT",
		Regex: &wrappers.BoolValue{Value: true},
	},
	{
		Name:  ":path",
		Value: "/bar",
		Regex: &wrappers.BoolValue{Value: true},
	},
}

var ExpectedHeaders3 = []*envoy_api_v2_route.HeaderMatcher{
	{
		Name:  ":method",
		Value: "GET",
		Regex: &wrappers.BoolValue{Value: true},
	},
	{
		Name:  ":path",
		Value: "/bar",
		Regex: &wrappers.BoolValue{Value: true},
	},
}

var EndpointSelector1 = v3.NewESFromLabels(
	&labels.Label{Key: "app", Value: "etcd", Source: labels.LabelSourceK8s},
)

var EndpointSelector2 = v3.NewESFromLabels(
	&labels.Label{Key: "version", Value: "v1", Source: labels.LabelSourceK8s},
)

var L7Rules1 = v3.L7Rules{HTTP: []v3.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}}

var L7Rules2 = v3.L7Rules{HTTP: []v3.PortRuleHTTP{*PortRuleHTTP1}}

var IdentityCache = identity.IdentityCache{
	1001: []*labels.Label{
		{Key: "app", Value: "etcd", Source: labels.LabelSourceK8s},
		{Key: "version", Value: "v1", Source: labels.LabelSourceK8s},
	},
	1002: []*labels.Label{
		{Key: "app", Value: "etcd", Source: labels.LabelSourceK8s},
		{Key: "version", Value: "v3", Source: labels.LabelSourceK8s},
	},
	1003: []*labels.Label{
		{Key: "app", Value: "cassandra", Source: labels.LabelSourceK8s},
		{Key: "version", Value: "v1", Source: labels.LabelSourceK8s},
	},
}

var DeniedIdentitiesNone = make(map[identity.NumericIdentity]bool)

var DeniedIdentities1001 = map[identity.NumericIdentity]bool{1001: true}

var ExpectedPortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1001, 1002},
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
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
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule3 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil, // Wildcard. Select all.
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule4 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1002}, // Like ExpectedPortNetworkPolicyRule1 but 1001 is denied.
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var ExpectedPortNetworkPolicyRule5 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1002, 1003}, // Wildcard, but 1001 is denied.
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{Headers: ExpectedHeaders2},
				{Headers: ExpectedHeaders1},
			},
		},
	},
}

var L4PolicyMap1 = map[string]policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: v3.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			EndpointSelector1: L7Rules1,
		},
	},
}

var L4PolicyMap2 = map[string]policy.L4Filter{
	"8080/UDP": {
		Port:     8080,
		Protocol: v3.ProtoUDP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			EndpointSelector2: L7Rules2,
		},
	},
}

var L4PolicyMap3 = map[string]policy.L4Filter{
	"8080/UDP": {
		Port:     80,
		Protocol: v3.ProtoTCP,
		L7Parser: policy.ParserTypeHTTP,
		L7RulesPerEp: policy.L7DataMap{
			policy.WildcardIdentitySelector: L7Rules1,
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

var ExpectedPerPortPolicies4 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule4,
		},
	},
}

var ExpectedPerPortPolicies5 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_api_v2_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule5,
		},
	},
}

var L4Policy1 = &policy.L4Policy{
	Ingress: L4PolicyMap1,
	Egress:  L4PolicyMap2,
}

var L4Policy2 = &policy.L4Policy{
	Ingress: L4PolicyMap3,
	Egress:  L4PolicyMap2,
}

func (s *ServerSuite) TestGetHTTPRule(c *C) {
	obtained, _ := getHTTPRule(PortRuleHTTP1)
	c.Assert(obtained, comparator.DeepEquals, ExpectedHeaders1)
}

func (s *ServerSuite) TestGetPortNetworkPolicyRule(c *C) {
	obtained := getPortNetworkPolicyRule(EndpointSelector1, policy.ParserTypeHTTP, L7Rules1,
		IdentityCache, DeniedIdentitiesNone)
	c.Assert(obtained, comparator.DeepEquals, ExpectedPortNetworkPolicyRule1)

	obtained = getPortNetworkPolicyRule(EndpointSelector2, policy.ParserTypeHTTP, L7Rules2,
		IdentityCache, DeniedIdentitiesNone)
	c.Assert(obtained, comparator.DeepEquals, ExpectedPortNetworkPolicyRule2)
}

func (s *ServerSuite) TestGetDirectionNetworkPolicy(c *C) {
	obtained := getDirectionNetworkPolicy(L4PolicyMap1, true, IdentityCache, DeniedIdentitiesNone)
	c.Assert(obtained, comparator.DeepEquals, ExpectedPerPortPolicies1)

	obtained = getDirectionNetworkPolicy(L4PolicyMap2, true, IdentityCache, DeniedIdentitiesNone)
	c.Assert(obtained, comparator.DeepEquals, ExpectedPerPortPolicies2)
}

func (s *ServerSuite) TestGetNetworkPolicy(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, L4Policy1, true, true, IdentityCache, DeniedIdentitiesNone, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies1,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcard(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, L4Policy2, true, true, IdentityCache, DeniedIdentitiesNone, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies3,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyDeny(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, L4Policy1, true, true, IdentityCache, DeniedIdentities1001, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies4,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyWildcardDeny(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, L4Policy2, true, true, IdentityCache, DeniedIdentities1001, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies5,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyNil(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, nil, true, true, IdentityCache, DeniedIdentities1001, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  nil,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyIngressNotEnforced(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, L4Policy2, false, true, IdentityCache, DeniedIdentities1001, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: allowAllPortNetworkPolicy,
		EgressPerPortPolicies:  ExpectedPerPortPolicies2,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}

func (s *ServerSuite) TestGetNetworkPolicyEgressNotEnforced(c *C) {
	obtained := getNetworkPolicy(IPv4Addr, Identity, L4Policy2, true, false, IdentityCache, DeniedIdentities1001, DeniedIdentitiesNone)
	expected := &cilium.NetworkPolicy{
		Name:                   IPv4Addr,
		Policy:                 uint64(Identity),
		IngressPerPortPolicies: ExpectedPerPortPolicies5,
		EgressPerPortPolicies:  allowAllPortNetworkPolicy,
	}
	c.Assert(obtained, comparator.DeepEquals, expected)
}
