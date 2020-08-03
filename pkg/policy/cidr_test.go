// Copyright 2018-2020 Authors of Cilium
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

package policy

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestgetPrefixesFromCIDR(c *C) {
	inputToCIDRString := map[string]string{
		"0.0.0.0/0":    "0.0.0.0/0",
		"192.0.2.3":    "192.0.2.3/32",
		"192.0.2.3/32": "192.0.2.3/32",
		"192.0.2.3/24": "192.0.2.0/24",
		"192.0.2.0/24": "192.0.2.0/24",
		"::/0":         "::/0",
		"fdff::ff":     "fdff::ff/128",
	}
	expected := []*net.IPNet{}
	inputs := []api.CIDR{}
	for ruleStr, cidr := range inputToCIDRString {
		_, net, err := net.ParseCIDR(cidr)
		c.Assert(err, IsNil)
		expected = append(expected, net)
		inputs = append(inputs, api.CIDR(ruleStr))
	}
	result := getPrefixesFromCIDR(inputs)
	c.Assert(result, checker.DeepEquals, expected)
}

func (ds *PolicyTestSuite) TestGetCIDRPrefixes(c *C) {
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromCIDR: []api.CIDR{
							"192.0.2.0/24",
						},
					},
				},
			},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToCIDR: []api.CIDR{
							"192.0.2.0/24",
							"192.0.3.0/24",
						},
					},
				},
			},
		},
	}

	// We have three CIDR instances in the ruleset, check that all exist
	expectedCIDRStrings := []string{
		"192.0.2.0/24",
		"192.0.2.0/24",
		"192.0.3.0/24",
	}
	expectedCIDRs := []*net.IPNet{}
	for _, ipStr := range expectedCIDRStrings {
		_, cidr, err := net.ParseCIDR(ipStr)
		c.Assert(err, IsNil)
		expectedCIDRs = append(expectedCIDRs, cidr)
	}
	c.Assert(GetCIDRPrefixes(rules), checker.DeepEquals, expectedCIDRs)

	// Now, test with CIDRSets.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromCIDRSet: []api.CIDRRule{
							{
								Cidr:        "192.0.2.0/24",
								ExceptCIDRs: []api.CIDR{"192.0.2.128/25"},
							},
						},
					},
				},
			},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToCIDRSet: []api.CIDRRule{
							{
								Cidr:        "10.0.0.0/8",
								ExceptCIDRs: []api.CIDR{"10.0.0.0/16"},
							},
						},
					},
				},
			},
		},
	}

	// Once exceptions apply, here are the list of CIDRs.
	expectedCIDRStrings = []string{
		"192.0.2.0/25",
		// Not "192.0.2.128/25",
		"10.128.0.0/9",
		"10.64.0.0/10",
		"10.32.0.0/11",
		"10.16.0.0/12",
		"10.8.0.0/13",
		"10.4.0.0/14",
		"10.2.0.0/15",
		"10.1.0.0/16",
		// Not "10.0.0.0/16",
	}
	expectedCIDRs = []*net.IPNet{}
	for _, ipStr := range expectedCIDRStrings {
		_, cidr, err := net.ParseCIDR(ipStr)
		c.Assert(err, IsNil)
		expectedCIDRs = append(expectedCIDRs, cidr)
	}
	c.Assert(GetCIDRPrefixes(rules), checker.DeepEquals, expectedCIDRs)
}
