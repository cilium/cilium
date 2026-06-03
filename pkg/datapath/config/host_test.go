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
	option.Config.EncryptionStrictEgressAllowRemoteNodeIdentities = true

	ep := testutils.NewTestEndpoint(t)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1}}

	for _, tt := range []struct {
		name            string
		enabled         bool
		nodeIPv4        string
		wantOverlapping bool
	}{
		{
			name:     "disabled",
			nodeIPv4: "192.0.2.1",
		},
		{
			name:            "overlapping",
			enabled:         true,
			nodeIPv4:        "192.0.2.1",
			wantOverlapping: true,
		},
		{
			name:     "not overlapping",
			enabled:  true,
			nodeIPv4: "198.51.100.1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EnableEncryptionStrictModeEgress = tt.enabled
			lnc := &Config{NodeIPv4: netip.MustParseAddr(tt.nodeIPv4)}

			cfg, ok := Netdev(&ep, lnc, link, netip.Addr{}, netip.Addr{}).(*BPFHost)
			require.True(t, ok)
			assert.Equal(t, tt.enabled, cfg.StrictEgressEncryption.Enabled)
			assert.Equal(t, tt.wantOverlapping, cfg.StrictEgressEncryption.IPv4Overlapping)

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
