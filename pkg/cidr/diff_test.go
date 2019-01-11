// Copyright 2019 Authors of Cilium
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

package cidr

import (
	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

func (s *CidrTestSuite) TestDiffIPNetLists(c *check.C) {
	net1 := MustParseCIDR("1.1.1.1/32")
	net2 := MustParseCIDR("1.1.1.1/24")
	net3 := MustParseCIDR("cafe::1/128")
	net4 := MustParseCIDR("cafe::2/16")

	type testExpectation struct {
		old    []*CIDR
		new    []*CIDR
		add    []*CIDR
		remove []*CIDR
	}

	expectations := []testExpectation{
		{old: []*CIDR{nil}, new: []*CIDR{net1, net2, net3, net4}, add: []*CIDR{net1, net2, net3, net4}, remove: nil},
		{old: []*CIDR{}, new: []*CIDR{net1, net2, net3, net4}, add: []*CIDR{net1, net2, net3, net4}, remove: nil},
		{old: []*CIDR{net1, net2, net3, net4}, new: []*CIDR{}, add: nil, remove: []*CIDR{net1, net2, net3, net4}},
		{old: []*CIDR{net1, net2}, new: []*CIDR{net3, net4}, add: []*CIDR{net3, net4}, remove: []*CIDR{net1, net2}},
		{old: []*CIDR{net1, net2}, new: []*CIDR{net2, net3}, add: []*CIDR{net3}, remove: []*CIDR{net1}},
		{old: []*CIDR{net1, net2, net3, net4}, new: []*CIDR{net1, net2, net3, net4}, add: nil, remove: nil},
	}

	for i, t := range expectations {
		add, remove := DiffCIDRLists(t.old, t.new)
		c.Assert(add, checker.DeepEquals, t.add, check.Commentf("test index: %d", i))
		c.Assert(remove, checker.DeepEquals, t.remove, check.Commentf("test index: %d", i))
	}
}
