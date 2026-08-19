// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestAddressCoveredByPrefix(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.0/28"),
	}

	tests := []struct {
		name     string
		addr     netip.Addr
		prefixes []netip.Prefix
		want     bool
	}{
		{"address in first prefix", netip.MustParseAddr("10.0.0.50"), prefixes, true},
		{"address in second prefix", netip.MustParseAddr("192.168.1.10"), prefixes, true},
		{"address outside all prefixes", netip.MustParseAddr("172.16.0.1"), prefixes, false},
		{"empty prefixes", netip.MustParseAddr("10.0.0.1"), nil, false},
		{"boundary - first address", netip.MustParseAddr("10.0.0.0"), prefixes, true},
		{"boundary - last address", netip.MustParseAddr("10.0.0.255"), prefixes, true},
		{"boundary - just outside", netip.MustParseAddr("10.0.1.0"), prefixes, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, addressCoveredByPrefix(tt.addr, tt.prefixes))
		})
	}
}

func TestPoolsAccessorFromResource(t *testing.T) {
	t.Run("no ENIs returns spec pools", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		result := poolAccessor.FromResource(node)
		require.Empty(t, result.Allocated)
	})

	t.Run("secondary IPs as /32 CIDRs", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				Addresses: addrs("10.0.0.1", "10.0.0.2"),
			},
		}

		result := poolAccessor.FromResource(node)
		require.Len(t, result.Allocated, 1)
		require.Equal(t, defaults.IPAMDefaultIPPool, result.Allocated[0].Pool)
		require.True(t, result.Allocated[0].AllowFirstIP)
		require.True(t, result.Allocated[0].AllowLastIP)
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")))
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")))
	})

	t.Run("prefix delegation writes prefixes and excludes covered addresses", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				// Mimics the pkg/aws/api.parseENI behavior: Addresses contains the ENI secondary
				// IPs, the ENI primary if UsePrimaryAddress and the 16 IPs expanded from the /28 prefix.
				// Prefixes contains the raw /28.
				Addresses: addrs(
					"10.0.0.1", // ENI primary IP (UsePrimaryAddress)
					"10.0.0.16", "10.0.0.17", "10.0.0.18", "10.0.0.19",
					"10.0.0.20", "10.0.0.21", "10.0.0.22", "10.0.0.23",
					"10.0.0.24", "10.0.0.25", "10.0.0.26", "10.0.0.27",
					"10.0.0.28", "10.0.0.29", "10.0.0.30", "10.0.0.31",
				),
				Prefixes: prefixes("10.0.0.16/28"),
			},
		}

		result := poolAccessor.FromResource(node)
		require.Len(t, result.Allocated, 1)
		require.Equal(t, defaults.IPAMDefaultIPPool, result.Allocated[0].Pool)
		require.True(t, result.Allocated[0].AllowFirstIP)
		require.True(t, result.Allocated[0].AllowLastIP)
		// Should contain the /28 prefix and the primary IP as /32,
		// but not the 16 expanded prefix IPs.
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28")))
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")))
		require.Len(t, result.Allocated[0].CIDRs, 2) // 1 prefix + 1 primary IP
	})

	t.Run("IPv6 prefixes are advertised as pool CIDRs", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				Addresses:    addrs("10.0.0.1"),
				Prefixes:     prefixes("10.0.0.16/28"),
				IPv6Prefixes: prefixes("2001:db8::/80"),
			},
		}

		result := poolAccessor.FromResource(node)
		require.Len(t, result.Allocated, 1)
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28")))
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")))
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::/80")))
	})

	t.Run("excluded ENIs are skipped", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Spec.ENI.ExcludeInterfaceTags = map[string]string{"skip": "true"}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				Addresses: addrs("10.0.0.1"),
				Tags:      map[string]string{"skip": "true"},
			},
			"eni-2": {
				Addresses: addrs("10.0.0.2"),
			},
		}

		result := poolAccessor.FromResource(node)
		require.Len(t, result.Allocated, 1)
		require.True(t, result.Allocated[0].AllowFirstIP)
		require.True(t, result.Allocated[0].AllowLastIP)
		require.Len(t, result.Allocated[0].CIDRs, 1)
		require.Contains(t, result.Allocated[0].CIDRs, iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")))
	})
}
