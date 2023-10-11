// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"net/netip"
	"testing"
)

func TestIntersects(t *testing.T) {
	type test struct {
		name       string
		from1, to1 string
		from2, to2 string
		expected   bool
	}
	tests := []test{
		{
			name:  "no overlap right",
			from1: "10.0.0.0", to1: "10.0.0.10",
			from2: "10.0.0.11", to2: "10.0.0.20",
			expected: false,
		},
		{
			name:  "right edge overlap",
			from1: "10.0.0.0", to1: "10.0.0.10",
			from2: "10.0.0.10", to2: "10.0.0.20",
			expected: true,
		},
		{
			name:  "right overlap",
			from1: "10.0.0.0", to1: "10.0.0.10",
			from2: "10.0.0.5", to2: "10.0.0.20",
			expected: true,
		},
		{
			name:  "full overlap",
			from1: "10.0.0.0", to1: "10.0.0.10",
			from2: "10.0.0.0", to2: "10.0.0.10",
			expected: true,
		},
		{
			name:  "left overlap",
			from1: "10.0.0.5", to1: "10.0.0.20",
			from2: "10.0.0.0", to2: "10.0.0.10",
			expected: true,
		},
		{
			name:  "left edge overlap",
			from1: "10.0.0.10", to1: "10.0.0.20",
			from2: "10.0.0.0", to2: "10.0.0.10",
			expected: true,
		},
		{
			name:  "no overlap left",
			from1: "10.0.0.11", to1: "10.0.0.20",
			from2: "10.0.0.0", to2: "10.0.0.10",
			expected: false,
		},
	}

	for _, subT := range tests {
		t.Run(subT.name, func(tt *testing.T) {
			from1 := netip.MustParseAddr(subT.from1)
			from2 := netip.MustParseAddr(subT.from2)
			to1 := netip.MustParseAddr(subT.to1)
			to2 := netip.MustParseAddr(subT.to2)

			got := intersect(from1, to1, from2, to2)
			if got != subT.expected {
				tt.Fatalf("%s, %s-%s / %s-%s, got: %v, expected %v", subT.name, from1, to1, from2, to2, got, subT.expected)
			}
		})
	}
}
