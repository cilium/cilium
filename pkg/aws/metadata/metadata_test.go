// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVPCIPv4CIDRs(t *testing.T) {
	tests := []struct {
		name       string
		primaryRaw string
		allRaw     string
		expected   []netip.Prefix
		expectErr  bool
	}{
		{
			name:       "single CIDR",
			primaryRaw: "10.128.0.0/16",
			allRaw:     "10.128.0.0/16",
			expected:   []netip.Prefix{netip.MustParsePrefix("10.128.0.0/16")},
		},
		{
			name:       "primary kept first, tail sorted",
			primaryRaw: "10.128.0.0/16",
			allRaw:     "10.132.0.0/16\n10.128.0.0/16\n10.0.0.0/16\n100.112.0.0/16",
			expected: []netip.Prefix{
				netip.MustParsePrefix("10.128.0.0/16"),
				netip.MustParsePrefix("10.0.0.0/16"),
				netip.MustParsePrefix("10.132.0.0/16"),
				netip.MustParsePrefix("100.112.0.0/16"),
			},
		},
		{
			name:       "unparsable primary",
			primaryRaw: "not-a-cidr",
			allRaw:     "10.128.0.0/16",
			expectErr:  true,
		},
		{
			name:       "unparsable association",
			primaryRaw: "10.128.0.0/16",
			allRaw:     "10.128.0.0/16\nnot-a-cidr",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidrs, err := parseVPCIPv4CIDRs(tt.primaryRaw, tt.allRaw)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cidrs)
		})
	}
}
