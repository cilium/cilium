// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package ipam

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
)

func TestParseIPv4EgressPoolSpec(t *testing.T) {
	spec, err := parseIPv4EgressPoolSpec([]string{"100.64.0.0/10", "198.18.1.0/16"}, 24)
	require.NoError(t, err)
	require.Equal(t, uint8(24), spec.MaskSize)
	require.Equal(t, []iputil.Prefix{
		iputil.PrefixFrom(netip.MustParsePrefix("100.64.0.0/10")),
		iputil.PrefixFrom(netip.MustParsePrefix("198.18.0.0/16")),
	}, spec.CIDRs)

	for name, tc := range map[string]struct {
		cidrs    []string
		maskSize int
	}{
		"invalid CIDR":       {[]string{"100.64.0.0"}, 24},
		"IPv6 CIDR":          {[]string{"fd00::/64"}, 24},
		"CIDR below mask":    {[]string{"100.64.0.0/26"}, 24},
		"mask size too big":  {[]string{"100.64.0.0/10"}, 33},
		"mask size negative": {[]string{"100.64.0.0/10"}, -1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseIPv4EgressPoolSpec(tc.cidrs, tc.maskSize)
			require.Error(t, err)
		})
	}
}
