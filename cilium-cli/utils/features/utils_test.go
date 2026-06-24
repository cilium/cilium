// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func TestComputeFailureExceptions(t *testing.T) {
	defaultExceptions := []string{"reason0", "reason1"}
	tests := []struct {
		inputExceptions    []string
		expectedExceptions []string
	}{
		// Empty list of reasons.
		{
			inputExceptions:    []string{},
			expectedExceptions: []string{},
		},
		// Add a reason to default list.
		{
			inputExceptions:    []string{"+reason2"},
			expectedExceptions: []string{"reason0", "reason1", "reason2"},
		},
		// Remove a reason from default list.
		{
			inputExceptions:    []string{"-reason1"},
			expectedExceptions: []string{"reason0"},
		},
		// Add a reason then remove it.
		{
			inputExceptions:    []string{"+reason2", "-reason2"},
			expectedExceptions: []string{"reason0", "reason1"},
		},
		// Remove a reason then add it back.
		{
			inputExceptions:    []string{"-reason1", "+reason1"},
			expectedExceptions: []string{"reason0", "reason1"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("InputExceptions: %v", test.inputExceptions), func(t *testing.T) {
			result := ComputeFailureExceptions(defaultExceptions, test.inputExceptions)

			// computeFailureExceptions doesn't guarantee the order of the
			// returned slice so we have to sort both slices.
			slices.Sort(result)
			if !reflect.DeepEqual(result, test.expectedExceptions) {
				t.Errorf("Expected exceptions to be %v, but got: %v", test.expectedExceptions, result)
			}
		})
	}
}

func TestSameSubnet(t *testing.T) {
	tests := []struct {
		name     string
		ip1      string
		ip2      string
		topology string
		expected bool
	}{
		{
			name:     "empty topology",
			ip1:      "10.0.0.1",
			ip2:      "10.0.0.2",
			topology: "",
			expected: false,
		},
		{
			name:     "same subnet single CIDR",
			ip1:      "10.0.0.1",
			ip2:      "10.0.0.2",
			topology: "10.0.0.0/24",
			expected: true,
		},
		{
			name:     "different subnets single CIDR",
			ip1:      "10.0.0.1",
			ip2:      "10.1.0.1",
			topology: "10.0.0.0/24",
			expected: false,
		},
		{
			name:     "same group multiple CIDRs",
			ip1:      "10.0.0.1",
			ip2:      "10.10.0.1",
			topology: "10.0.0.0/24,10.10.0.0/24",
			expected: true,
		},
		{
			name:     "different groups",
			ip1:      "10.0.0.1",
			ip2:      "10.20.0.1",
			topology: "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24",
			expected: false,
		},
		{
			name:     "same group second group",
			ip1:      "10.20.0.1",
			ip2:      "10.20.0.2",
			topology: "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24",
			expected: true,
		},
		{
			name:     "ipv6 same subnet",
			ip1:      "2001:db8:85a3::1",
			ip2:      "2001:db8:85a3::2",
			topology: "2001:db8:85a3::/64",
			expected: true,
		},
		{
			name:     "ipv6 different subnets",
			ip1:      "2001:db8:85a3::1",
			ip2:      "2001:db8:85a4::1",
			topology: "2001:db8:85a3::/64",
			expected: false,
		},
		{
			name:     "mixed ipv4 and ipv6 in same group",
			ip1:      "10.0.0.1",
			ip2:      "2001:db8:85a3::1",
			topology: "10.0.0.0/24,2001:db8:85a3::/64",
			expected: true, // both IPs are in CIDRs within the same group
		},
		{
			name:     "invalid ip1",
			ip1:      "invalid",
			ip2:      "10.0.0.2",
			topology: "10.0.0.0/24",
			expected: false,
		},
		{
			name:     "invalid ip2",
			ip1:      "10.0.0.1",
			ip2:      "invalid",
			topology: "10.0.0.0/24",
			expected: false,
		},
		{
			name:     "complex topology with three groups",
			ip1:      "10.0.0.1",
			ip2:      "10.10.0.1",
			topology: "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24;2001:db8:85a3::/64",
			expected: true,
		},
		{
			name:     "ip1 in group but ip2 not in any group",
			ip1:      "10.0.0.1",
			ip2:      "192.168.1.1",
			topology: "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24",
			expected: false,
		},
		{
			name:     "both IPs in different CIDRs within same group",
			ip1:      "10.0.0.5",
			ip2:      "10.10.0.5",
			topology: "10.0.0.0/24,10.10.0.0/24",
			expected: true,
		},
		{
			name:     "topology with spaces",
			ip1:      "10.0.0.1",
			ip2:      "10.10.0.1",
			topology: "10.0.0.0/24 , 10.10.0.0/24 ; 10.20.0.0/24",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SameSubnet(tt.ip1, tt.ip2, tt.topology)
			if result != tt.expected {
				t.Errorf("SameSubnet(%q, %q, %q) = %v, want %v",
					tt.ip1, tt.ip2, tt.topology, result, tt.expected)
			}
		})
	}
}
