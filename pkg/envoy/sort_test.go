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

	"github.com/cilium/proxy/go/cilium/api"
	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/proxy/go/envoy/api/v2/route"
	. "gopkg.in/check.v1"
)

type SortSuite struct{}

var _ = Suite(&SortSuite{})

var HeaderMatcher1 = &envoy_api_v2_route.HeaderMatcher{
	Name:                 "aaa",
	HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "aaa"},
}

var HeaderMatcher2 = &envoy_api_v2_route.HeaderMatcher{
	Name:                 "bbb",
	HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "aaa"},
}

var HeaderMatcher3 = &envoy_api_v2_route.HeaderMatcher{
	Name:                 "bbb",
	HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "bbb"},
}

var HeaderMatcher4 = &envoy_api_v2_route.HeaderMatcher{
	Name:                 "bbb",
	HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "bbb"},
}

func (s *SortSuite) TestSortHeaderMatchers(c *C) {
	var slice, expected []*envoy_api_v2_route.HeaderMatcher

	slice = []*envoy_api_v2_route.HeaderMatcher{
		HeaderMatcher4,
		HeaderMatcher3,
		HeaderMatcher2,
		HeaderMatcher1,
	}
	expected = []*envoy_api_v2_route.HeaderMatcher{
		HeaderMatcher1,
		HeaderMatcher2,
		HeaderMatcher3,
		HeaderMatcher4,
	}
	SortHeaderMatchers(slice)
	c.Assert(slice, checker.DeepEquals, expected)
}

var HTTPNetworkPolicyRule1 = &cilium.HttpNetworkPolicyRule{}

var HTTPNetworkPolicyRule2 = &cilium.HttpNetworkPolicyRule{
	Headers: []*envoy_api_v2_route.HeaderMatcher{HeaderMatcher1},
}

var HTTPNetworkPolicyRule3 = &cilium.HttpNetworkPolicyRule{
	Headers: []*envoy_api_v2_route.HeaderMatcher{HeaderMatcher1, HeaderMatcher2},
}

var HTTPNetworkPolicyRule4 = &cilium.HttpNetworkPolicyRule{
	Headers: []*envoy_api_v2_route.HeaderMatcher{HeaderMatcher1, HeaderMatcher3},
}

func (s *SortSuite) TestSortHttpNetworkPolicyRules(c *C) {
	var slice, expected []*cilium.HttpNetworkPolicyRule

	slice = []*cilium.HttpNetworkPolicyRule{
		HTTPNetworkPolicyRule4,
		HTTPNetworkPolicyRule3,
		HTTPNetworkPolicyRule2,
		HTTPNetworkPolicyRule1,
	}
	expected = []*cilium.HttpNetworkPolicyRule{
		HTTPNetworkPolicyRule1,
		HTTPNetworkPolicyRule2,
		HTTPNetworkPolicyRule3,
		HTTPNetworkPolicyRule4,
	}
	SortHTTPNetworkPolicyRules(slice)
	c.Assert(slice, checker.DeepEquals, expected)
}

var PortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil,
	L7:             nil,
}

var PortNetworkPolicyRule2 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1},
	L7:             nil,
}

var PortNetworkPolicyRule3 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7:             nil,
}

var PortNetworkPolicyRule4 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil,
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
			},
		},
	},
}

var PortNetworkPolicyRule5 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
			},
		},
	},
}

var PortNetworkPolicyRule6 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
				HTTPNetworkPolicyRule2,
			},
		},
	},
}

var PortNetworkPolicyRule7 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
				HTTPNetworkPolicyRule3,
			},
		},
	},
}

// TODO: Test sorting Kafka rules.

func (s *SortSuite) TestSortPortNetworkPolicyRules(c *C) {
	var slice, expected []*cilium.PortNetworkPolicyRule

	slice = []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule7,
		PortNetworkPolicyRule6,
		PortNetworkPolicyRule5,
		PortNetworkPolicyRule4,
		PortNetworkPolicyRule3,
		PortNetworkPolicyRule2,
		PortNetworkPolicyRule1,
	}
	expected = []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
		PortNetworkPolicyRule2,
		PortNetworkPolicyRule3,
		PortNetworkPolicyRule4,
		PortNetworkPolicyRule5,
		PortNetworkPolicyRule6,
		PortNetworkPolicyRule7,
	}
	SortPortNetworkPolicyRules(slice)
	c.Assert(slice, checker.DeepEquals, expected)
}

var PortNetworkPolicy1 = &cilium.PortNetworkPolicy{
	Protocol: envoy_api_v2_core.SocketAddress_TCP,
	Port:     10001,
	Rules:    nil,
}

var PortNetworkPolicy2 = &cilium.PortNetworkPolicy{
	Protocol: envoy_api_v2_core.SocketAddress_UDP,
	Port:     10001,
	Rules:    nil,
}

var PortNetworkPolicy3 = &cilium.PortNetworkPolicy{
	Protocol: envoy_api_v2_core.SocketAddress_UDP,
	Port:     10002,
	Rules:    nil,
}

var PortNetworkPolicy4 = &cilium.PortNetworkPolicy{
	Protocol: envoy_api_v2_core.SocketAddress_UDP,
	Port:     10002,
	Rules: []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
	},
}

var PortNetworkPolicy5 = &cilium.PortNetworkPolicy{
	Protocol: envoy_api_v2_core.SocketAddress_UDP,
	Port:     10002,
	Rules: []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
		PortNetworkPolicyRule2,
	},
}

var PortNetworkPolicy6 = &cilium.PortNetworkPolicy{
	Protocol: envoy_api_v2_core.SocketAddress_UDP,
	Port:     10002,
	Rules: []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
		PortNetworkPolicyRule3,
	},
}

func (s *SortSuite) TestSortPortNetworkPolicies(c *C) {
	var slice, expected []*cilium.PortNetworkPolicy

	slice = []*cilium.PortNetworkPolicy{
		PortNetworkPolicy6,
		PortNetworkPolicy5,
		PortNetworkPolicy4,
		PortNetworkPolicy3,
		PortNetworkPolicy2,
		PortNetworkPolicy1,
	}
	expected = []*cilium.PortNetworkPolicy{
		PortNetworkPolicy1,
		PortNetworkPolicy2,
		PortNetworkPolicy3,
		PortNetworkPolicy4,
		PortNetworkPolicy5,
		PortNetworkPolicy6,
	}
	SortPortNetworkPolicies(slice)
	c.Assert(slice, checker.DeepEquals, expected)
}
