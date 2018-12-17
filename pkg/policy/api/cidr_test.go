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

package api

import (
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	cidrpkg "github.com/cilium/cilium/pkg/labels/cidr"

	. "gopkg.in/check.v1"
)

func (s *PolicyAPITestSuite) TestCIDRMatchesAll(c *C) {
	cidr := CIDR("0.0.0.0/0")
	c.Assert(cidr.MatchesAll(), Equals, true)

	cidr = CIDR("::/0")
	c.Assert(cidr.MatchesAll(), Equals, true)

	cidr = CIDR("192.0.2.0/24")
	c.Assert(cidr.MatchesAll(), Equals, false)
	cidr = CIDR("192.0.2.3/32")
	c.Assert(cidr.MatchesAll(), Equals, false)
}

func (s *PolicyAPITestSuite) TestGetAsEndpointSelectors(c *C) {
	world := labels.ParseLabelArray("reserved:world")

	labelWorld := labels.ParseSelectLabel("reserved:world")
	esWorld := NewESFromLabels(labelWorld)

	labelAllV4, err := cidrpkg.IPStringToLabel("0.0.0.0/0")
	c.Assert(err, IsNil)
	v4World := NewESFromLabels(labelAllV4)

	labelAllV6, err := cidrpkg.IPStringToLabel("::/0")
	c.Assert(err, IsNil)
	v6World := NewESFromLabels(labelAllV6)

	labelOtherCIDR, err := cidrpkg.IPStringToLabel("192.168.128.0/24")
	c.Assert(err, IsNil)
	esOtherCIDR := NewESFromLabels(labelOtherCIDR)

	cidrs := CIDRSlice{
		"0.0.0.0/0",
	}

	expectedSelectors := EndpointSelectorSlice{
		esWorld,
		v4World,
	}
	result := cidrs.GetAsEndpointSelectors()
	c.Assert(result.Matches(world), Equals, true)
	c.Assert(result, checker.DeepEquals, expectedSelectors)

	cidrs = CIDRSlice{
		"::/0",
	}
	expectedSelectors = EndpointSelectorSlice{
		esWorld,
		v6World,
	}
	result = cidrs.GetAsEndpointSelectors()
	c.Assert(result.Matches(world), Equals, true)
	c.Assert(result, checker.DeepEquals, expectedSelectors)

	cidrs = CIDRSlice{
		"0.0.0.0/0",
		"::/0",
		"192.168.128.10/24",
	}
	expectedSelectors = EndpointSelectorSlice{
		esWorld,
		v4World,
		v6World,
		esOtherCIDR,
	}
	result = cidrs.GetAsEndpointSelectors()
	c.Assert(result.Matches(world), Equals, true)
	c.Assert(result, checker.DeepEquals, expectedSelectors)
}
