// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
)

func TestConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := populateTestConfig(t, nil)
		require.NoError(t, err)
		require.False(t, cfg.IsEnabled())
		require.True(t, cfg.AddressAllowed(netip.MustParseAddr("192.0.2.1")))
		require.True(t, cfg.AddressAllowed(netip.MustParseAddr("2001:db8::1")))
	})

	t.Run("enabled with address matcher CIDRs", func(t *testing.T) {
		cfg, err := populateTestConfig(t, map[string]any{
			EnableLocalRedirectPolicyName: true,
			AddressMatcherCIDRsName:       []string{"10.0.0.0/8", "2001:db8::/32"},
		})
		require.NoError(t, err)
		require.True(t, cfg.IsEnabled())

		addresses := []struct {
			name    string
			address netip.Addr
			allowed bool
		}{
			{
				name:    "IPv4 address inside configured CIDR",
				address: netip.MustParseAddr("10.0.0.1"),
				allowed: true,
			},
			{
				name:    "IPv6 address inside configured CIDR",
				address: netip.MustParseAddr("2001:db8::1"),
				allowed: true,
			},
			{
				name:    "address outside configured CIDRs",
				address: netip.MustParseAddr("192.0.2.1"),
				allowed: false,
			},
		}

		for _, tt := range addresses {
			t.Run(tt.name, func(t *testing.T) {
				require.Equal(t, tt.allowed, cfg.AddressAllowed(tt.address))
			})
		}
	})

	t.Run("invalid address matcher CIDR", func(t *testing.T) {
		_, err := populateTestConfig(t, map[string]any{
			AddressMatcherCIDRsName: []string{"not-a-cidr"},
		})
		require.Error(t, err)
	})
}

func populateTestConfig(t *testing.T, values map[string]any) (Config, error) {
	t.Helper()

	var cfg Config
	h := hive.New(
		ConfigCell,
		cell.Invoke(func(config Config) {
			cfg = config
		}),
	)
	for name, value := range values {
		h.Viper().Set(name, value)
	}

	err := h.Populate(hivetest.Logger(t))
	return cfg, err
}
