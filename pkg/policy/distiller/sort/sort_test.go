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

package sort

import (
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"

	"github.com/golang/protobuf/ptypes/wrappers"

	. "gopkg.in/check.v1"
)

type SortSuite struct{}

var _ = Suite(&SortSuite{})

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

var KafkaNetworkPolicyRule1 = &cilium.KafkaNetworkPolicyRule{}

var KafkaNetworkPolicyRule2 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: -1,
	Topic:      "",
	ClientId:   "",
}

var KafkaNetworkPolicyRule3 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: -1,
	Topic:      "",
	ClientId:   "",
}

var KafkaNetworkPolicyRule4 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: 0,
	Topic:      "",
	ClientId:   "",
}

var KafkaNetworkPolicyRule5 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: 0,
	Topic:      "",
	ClientId:   "",
}

var KafkaNetworkPolicyRule6 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: 0,
	Topic:      "bar",
	ClientId:   "",
}

var KafkaNetworkPolicyRule7 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: 0,
	Topic:      "foo",
	ClientId:   "",
}

var KafkaNetworkPolicyRule8 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: 0,
	Topic:      "foo",
	ClientId:   "joe",
}

var KafkaNetworkPolicyRule9 = &cilium.KafkaNetworkPolicyRule{
	ApiKey:     -1,
	ApiVersion: 0,
	Topic:      "foo",
	ClientId:   "romain",
}

func (s *SortSuite) TestSortKafkaPolicyRules(c *C) {
	var slice, expected []*cilium.KafkaNetworkPolicyRule

	slice = []*cilium.KafkaNetworkPolicyRule{
		KafkaNetworkPolicyRule9,
		KafkaNetworkPolicyRule8,
		KafkaNetworkPolicyRule7,
		KafkaNetworkPolicyRule6,
		KafkaNetworkPolicyRule5,
		KafkaNetworkPolicyRule4,
		KafkaNetworkPolicyRule3,
		KafkaNetworkPolicyRule2,
		KafkaNetworkPolicyRule1,
	}
	expected = []*cilium.KafkaNetworkPolicyRule{
		KafkaNetworkPolicyRule2,
		KafkaNetworkPolicyRule3,
		KafkaNetworkPolicyRule4,
		KafkaNetworkPolicyRule5,
		KafkaNetworkPolicyRule6,
		KafkaNetworkPolicyRule7,
		KafkaNetworkPolicyRule8,
		KafkaNetworkPolicyRule9,
		KafkaNetworkPolicyRule1,
	}
	SortKafkaNetworkPolicyRules(slice)
	c.Assert(slice, comparator.DeepEquals, expected)
}

var HeaderMatcher1 = &envoy_api_v2_route.HeaderMatcher{
	Name:  "aaa",
	Value: "aaa",
	Regex: &wrappers.BoolValue{Value: false},
}

var HeaderMatcher2 = &envoy_api_v2_route.HeaderMatcher{
	Name:  "bbb",
	Value: "aaa",
	Regex: &wrappers.BoolValue{Value: false},
}

var HeaderMatcher3 = &envoy_api_v2_route.HeaderMatcher{
	Name:  "bbb",
	Value: "bbb",
	Regex: &wrappers.BoolValue{Value: false},
}

var HeaderMatcher4 = &envoy_api_v2_route.HeaderMatcher{
	Name:  "bbb",
	Value: "bbb",
	Regex: &wrappers.BoolValue{Value: true},
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
	c.Assert(slice, DeepEquals, expected)
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
	c.Assert(slice, DeepEquals, expected)
}

var PortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil,
	L7Rules:        nil,
}

var PortNetworkPolicyRule2 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1},
	L7Rules:        nil,
}

var PortNetworkPolicyRule3 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7Rules:        nil,
}

var PortNetworkPolicyRule4 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil,
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
			},
		},
	},
}

var PortNetworkPolicyRule5 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
			},
		},
	},
}

var PortNetworkPolicyRule6 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
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
	L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				HTTPNetworkPolicyRule1,
				HTTPNetworkPolicyRule3,
			},
		},
	},
}

var PortNetworkPolicyRule8 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint64{1, 2},
	L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
		KafkaRules: &cilium.KafkaNetworkPolicyRules{
			KafkaRules: []*cilium.KafkaNetworkPolicyRule{
				KafkaNetworkPolicyRule2,
				KafkaNetworkPolicyRule1,
			},
		},
	},
}

// TODO: Test sorting Kafka rules.

func (s *SortSuite) TestSortPortNetworkPolicyRules(c *C) {
	var slice, expected []*cilium.PortNetworkPolicyRule

	slice = []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule8,
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
		PortNetworkPolicyRule8,
		PortNetworkPolicyRule4,
		PortNetworkPolicyRule5,
		PortNetworkPolicyRule6,
		PortNetworkPolicyRule7,
	}
	SortPortNetworkPolicyRules(slice)
	c.Assert(slice, comparator.DeepEquals, expected)
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
	c.Assert(slice, DeepEquals, expected)
}
