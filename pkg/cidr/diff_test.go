// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
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
