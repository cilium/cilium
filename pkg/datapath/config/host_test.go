// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestNetdevStrictEgressEncryptionConfig(t *testing.T) {
	oldEnabled := option.Config.EnableEncryptionStrictModeEgress
	oldCIDR := option.Config.EncryptionStrictEgressCIDR
	oldAllowRemoteNodeIdentities := option.Config.EncryptionStrictEgressAllowRemoteNodeIdentities
	t.Cleanup(func() {
		option.Config.EnableEncryptionStrictModeEgress = oldEnabled
		option.Config.EncryptionStrictEgressCIDR = oldCIDR
		option.Config.EncryptionStrictEgressAllowRemoteNodeIdentities = oldAllowRemoteNodeIdentities
	})

	option.Config.EncryptionStrictEgressCIDR = netip.MustParsePrefix("192.0.2.0/24")

	ep := testutils.NewTestEndpoint(t)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1}}

	for _, tt := range []struct {
		name                      string
		enabled                   bool
		allowRemoteNodeIdentities bool
		nodeIPv4                  string
		wantAllowRemoteNodes      bool
	}{
		{
			name:                      "disabled",
			allowRemoteNodeIdentities: true,
			nodeIPv4:                  "192.0.2.1",
		},
		{
			name:                      "local node inside strict CIDR",
			enabled:                   true,
			allowRemoteNodeIdentities: true,
			nodeIPv4:                  "192.0.2.1",
			wantAllowRemoteNodes:      true,
		},
		{
			name:                      "local node outside strict CIDR",
			enabled:                   true,
			allowRemoteNodeIdentities: true,
			nodeIPv4:                  "198.51.100.1",
			wantAllowRemoteNodes:      true,
		},
		{
			name:     "remote node identities disabled",
			enabled:  true,
			nodeIPv4: "198.51.100.1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EnableEncryptionStrictModeEgress = tt.enabled
			option.Config.EncryptionStrictEgressAllowRemoteNodeIdentities = tt.allowRemoteNodeIdentities
			lnc := &Config{NodeIPv4: netip.MustParseAddr(tt.nodeIPv4)}

			cfg, ok := Netdev(&ep, lnc, link, netip.Addr{}, netip.Addr{}).(*BPFHost)
			require.True(t, ok)
			assert.Equal(t, tt.enabled, cfg.StrictEgressEncryption.Enabled)
			assert.Equal(t, tt.wantAllowRemoteNodes, cfg.StrictEgressEncryption.AllowRemoteNodes)

			if !tt.enabled {
				assert.Equal(t, uint8(0), cfg.StrictEgressEncryption.IPv4NetSize)
				return
			}

			assert.Equal(t, [4]byte{192, 0, 2, 0}, cfg.StrictEgressEncryption.IPv4Net.Addr)
			assert.Equal(t, netip.MustParseAddr(tt.nodeIPv4).As4(), cfg.StrictEgressEncryption.IPv4EncryptIface.Addr)
			assert.Equal(t, uint8(24), cfg.StrictEgressEncryption.IPv4NetSize)
		})
	}
}
