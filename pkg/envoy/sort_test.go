// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	. "github.com/cilium/checkmate"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher "github.com/cilium/proxy/go/envoy/type/matcher/v3"

	"github.com/cilium/cilium/pkg/checker"
)

type SortSuite struct{}

var _ = Suite(&SortSuite{})

var HeaderMatcher1 = &envoy_config_route.HeaderMatcher{
	Name: "aaa",
	HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher.StringMatcher{
			MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher.RegexMatcher{
					Regex: "aaa",
				},
			},
		},
	},
}

var HeaderMatcher2 = &envoy_config_route.HeaderMatcher{
	Name: "bbb",
	HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher.StringMatcher{
			MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher.RegexMatcher{
					Regex: "bbb",
				},
			},
		},
	},
}

var HeaderMatcher3 = &envoy_config_route.HeaderMatcher{
	Name: "bbb",
	HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher.StringMatcher{
			MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher.RegexMatcher{
					Regex: "bbb",
				},
			},
		},
	},
}

var HeaderMatcher4 = &envoy_config_route.HeaderMatcher{
	Name: "bbb",
	HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher.StringMatcher{
			MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher.RegexMatcher{
					Regex: "bbb",
				},
			},
		},
	},
}

func (s *SortSuite) TestSortHeaderMatchers(c *C) {
	var slice, expected []*envoy_config_route.HeaderMatcher

	slice = []*envoy_config_route.HeaderMatcher{
		HeaderMatcher4,
		HeaderMatcher3,
		HeaderMatcher2,
		HeaderMatcher1,
	}
	expected = []*envoy_config_route.HeaderMatcher{
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
	Headers: []*envoy_config_route.HeaderMatcher{HeaderMatcher1},
}

var HTTPNetworkPolicyRule3 = &cilium.HttpNetworkPolicyRule{
	Headers: []*envoy_config_route.HeaderMatcher{HeaderMatcher1, HeaderMatcher2},
}

var HTTPNetworkPolicyRule4 = &cilium.HttpNetworkPolicyRule{
	Headers: []*envoy_config_route.HeaderMatcher{HeaderMatcher1, HeaderMatcher3},
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
	Protocol: envoy_config_core.SocketAddress_TCP,
	Port:     10001,
	Rules:    nil,
}

var PortNetworkPolicy2 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10001,
	Rules:    nil,
}

var PortNetworkPolicy3 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10002,
	Rules:    nil,
}

var PortNetworkPolicy4 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10002,
	Rules: []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
	},
}

var PortNetworkPolicy5 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10002,
	Rules: []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
		PortNetworkPolicyRule2,
	},
}

var PortNetworkPolicy6 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
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
