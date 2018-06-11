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

package api

import (
	"github.com/cilium/cilium/pkg/labels"

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

	// Special case: the 0.0.0.0/0 CIDR should match reserved:world.
	world := labels.ParseLabelArray("reserved:world")
	cidrs := CIDRSlice{
		"0.0.0.0/0",
	}
	result := cidrs.GetAsEndpointSelectors()
	c.Assert(result[0].Matches(world), Equals, true)
}
