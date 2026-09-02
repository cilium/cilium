// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/mac"
)

func TestNewRoutingInfo(t *testing.T) {
	t.Run("no options", func(t *testing.T) {
		tests := []struct {
			name     string
			gateway  string
			macAddr  mac.MAC
			ifaceNum string
			wantErr  bool
		}{
			{
				name:     "invalid gateway",
				gateway:  "",
				macAddr:  mac.MustParseMAC("11:22:33:44:55:66"),
				ifaceNum: "1",
				wantErr:  true,
			},
			{
				name:     "empty mac address",
				gateway:  "192.168.1.1",
				macAddr:  mac.MAC{},
				ifaceNum: "1",
				wantErr:  true,
			},
			{
				name:     "invalid interface number",
				gateway:  "192.168.1.1",
				macAddr:  mac.MustParseMAC("11:22:33:44:55:66"),
				ifaceNum: "a",
				wantErr:  true,
			},
			{
				name:     "valid input",
				gateway:  "192.168.1.1",
				macAddr:  mac.MustParseMAC("11:22:33:44:55:66"),
				ifaceNum: "1",
				wantErr:  false,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rInfo, err := NewRoutingInfo(tt.gateway, tt.macAddr, tt.ifaceNum)
				require.Equal(t, tt.wantErr, err != nil)
				if tt.wantErr {
					require.Nil(t, rInfo)
					return
				}

				require.Equal(t, net.ParseIP(tt.gateway), rInfo.Gateway)
				require.Nil(t, rInfo.CIDRs)
				require.Equal(t, tt.macAddr, rInfo.MasterIfMAC)
				require.False(t, rInfo.Masquerade)
				require.Equal(t, 1, rInfo.InterfaceNumber)
				require.Nil(t, rInfo.mtu)
				require.Nil(t, rInfo.linkState)
				require.False(t, rInfo.compatEgressPriority)
			})
		}
	})
	t.Run("with options", func(t *testing.T) {
		rInfo, err := NewRoutingInfo(
			"192.168.1.1",
			mac.MustParseMAC("11:22:33:44:55:66"),
			"2",
			WithCIDRsAndMasquerade([]string{"192.168.0.0/16"}, true),
			WithMTU(1500),
			WithLinkState(true),
			WithCompatEgressPriority(),
		)
		require.NoError(t, err)

		_, cidr, err := net.ParseCIDR("192.168.0.0/16")
		require.NoError(t, err)
		require.Equal(t, []net.IPNet{*cidr}, rInfo.CIDRs)
		require.True(t, rInfo.Masquerade)
		require.NotNil(t, rInfo.mtu)
		require.Equal(t, 1500, *rInfo.mtu)
		require.NotNil(t, rInfo.linkState)
		require.True(t, *rInfo.linkState)
		require.True(t, rInfo.compatEgressPriority)

		require.NoError(t, rInfo.WithOptions(WithMTU(1400), WithLinkState(false)))
		require.Equal(t, 1400, *rInfo.mtu)
		require.False(t, *rInfo.linkState)
	})
	t.Run("CIDR option validation", func(t *testing.T) {
		for _, tt := range []struct {
			name       string
			cidrs      []string
			masquerade bool
		}{
			{
				name:       "invalid CIDR",
				cidrs:      []string{"192.168.0.0/33"},
				masquerade: true,
			},
			{
				name:       "empty CIDRs with masquerading",
				masquerade: true,
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				rInfo, err := NewRoutingInfo(
					"192.168.1.1",
					mac.MustParseMAC("11:22:33:44:55:66"),
					"1",
					WithCIDRsAndMasquerade(tt.cidrs, tt.masquerade),
				)
				require.Error(t, err)
				require.Nil(t, rInfo)
			})
		}
	})

}
