// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func TestNewRSSConfig(t *testing.T) {
	directRoutingDevice := &tables.Device{
		Addrs: []tables.DeviceAddress{
			{Addr: netip.MustParseAddr("192.0.2.10")},
			{Addr: netip.MustParseAddr("2001:db8::10")},
		},
	}

	tests := []struct {
		name         string
		ipv4Prefix   netip.Prefix
		ipv6Prefix   netip.Prefix
		device       *tables.Device
		expectedIPv4 netip.Prefix
		expectedIPv6 netip.Prefix
	}{
		{
			name:         "configured prefixes",
			ipv4Prefix:   netip.MustParsePrefix("198.51.100.0/24"),
			ipv6Prefix:   netip.MustParsePrefix("2001:db8:1::/64"),
			device:       directRoutingDevice,
			expectedIPv4: netip.MustParsePrefix("198.51.100.0/24"),
			expectedIPv6: netip.MustParsePrefix("2001:db8:1::/64"),
		},
		{
			name:         "direct-routing device fallbacks",
			device:       directRoutingDevice,
			expectedIPv4: netip.MustParsePrefix("192.0.2.10/32"),
			expectedIPv6: netip.MustParsePrefix("2001:db8::10/128"),
		},
		{
			name:         "unspecified fallbacks",
			expectedIPv4: netip.MustParsePrefix("0.0.0.0/32"),
			expectedIPv6: netip.MustParsePrefix("::/128"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NewRSSConfig(tt.ipv4Prefix, tt.ipv6Prefix, tt.device)
			require.Equal(t, tt.expectedIPv4, actual.IPv4Prefix())
			require.Equal(t, tt.expectedIPv6, actual.IPv6Prefix())
		})
	}
}
