// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package topology

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Entry
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []Entry{},
			wantErr:  false,
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: []Entry{},
			wantErr:  false,
		},
		{
			name:  "single CIDR",
			input: "10.0.0.0/24",
			expected: []Entry{
				{Key: netip.MustParsePrefix("10.0.0.0/24"), Value: 1},
			},
			wantErr: false,
		},
		{
			name:  "two CIDRs in same group",
			input: "10.0.0.0/24,10.10.0.0/24",
			expected: []Entry{
				{Key: netip.MustParsePrefix("10.0.0.0/24"), Value: 1},
				{Key: netip.MustParsePrefix("10.10.0.0/24"), Value: 1},
			},
			wantErr: false,
		},
		{
			name:  "two groups with semicolon separator",
			input: "10.0.0.0/24;10.20.0.0/24",
			expected: []Entry{
				{Key: netip.MustParsePrefix("10.0.0.0/24"), Value: 1},
				{Key: netip.MustParsePrefix("10.20.0.0/24"), Value: 2},
			},
			wantErr: false,
		},
		{
			name:  "complex topology from CFP example",
			input: "10.0.0.1/24,10.10.0.1/24;10.20.0.1/24;2001:0db8:85a3::/64",
			expected: []Entry{
				{Key: netip.MustParsePrefix("10.0.0.1/24"), Value: 1},
				{Key: netip.MustParsePrefix("10.10.0.1/24"), Value: 1},
				{Key: netip.MustParsePrefix("10.20.0.1/24"), Value: 2},
				{Key: netip.MustParsePrefix("2001:db8:85a3::/64"), Value: 3},
			},
			wantErr: false,
		},
		{
			name:  "topology with whitespace",
			input: " 10.0.0.0/24 , 10.10.0.0/24 ; 10.20.0.0/24 ",
			expected: []Entry{
				{Key: netip.MustParsePrefix("10.0.0.0/24"), Value: 1},
				{Key: netip.MustParsePrefix("10.10.0.0/24"), Value: 1},
				{Key: netip.MustParsePrefix("10.20.0.0/24"), Value: 2},
			},
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			input:   "not-a-cidr",
			wantErr: true,
		},
		{
			name:    "partially invalid - one bad CIDR",
			input:   "10.0.0.0/24,invalid",
			wantErr: true,
		},
		{
			name:  "ipv6 only",
			input: "2001:db8::/32,fd00::/8",
			expected: []Entry{
				{Key: netip.MustParsePrefix("2001:db8::/32"), Value: 1},
				{Key: netip.MustParsePrefix("fd00::/8"), Value: 1},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Decode(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, result, len(tt.expected))
			for i, entry := range result {
				assert.Equal(t, tt.expected[i].Key, entry.Key, "entry %d key mismatch", i)
				assert.Equal(t, tt.expected[i].Value, entry.Value, "entry %d value (group ID) mismatch", i)
			}
		})
	}
}
