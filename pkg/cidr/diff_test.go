// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiffIPNetLists(t *testing.T) {
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

	for i, tt := range expectations {
		add, remove := DiffCIDRLists(tt.old, tt.new)
		require.Equalf(t, tt.add, add, "test index: %d", i)
		require.Equalf(t, tt.remove, remove, "test index: %d", i)
	}
}
