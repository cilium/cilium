// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
)

func TestDirectRoutingDeviceHasAddr(t *testing.T) {
	// Save and restore global config.
	savedIPv4 := option.Config.EnableIPv4
	savedIPv6 := option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4 = savedIPv4
		option.Config.EnableIPv6 = savedIPv6
	})
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	tests := []struct {
		name  string
		addrs []tables.DeviceAddress
		want  bool
	}{
		{
			name: "both addresses",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("192.0.2.1")},
				{Addr: netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
		{
			name: "only IPv4",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("192.0.2.1")},
			},
			want: true,
		},
		{
			name: "only IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
		{
			name:  "no addresses",
			addrs: nil,
			want:  false,
		},
		{
			name: "only unspecified IPv4",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("0.0.0.0")},
			},
			want: false,
		},
		{
			name: "only unspecified IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("::")},
			},
			want: false,
		},
		{
			name: "both unspecified",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("0.0.0.0")},
				{Addr: netip.MustParseAddr("::")},
			},
			want: false,
		},
		{
			name: "valid IPv4 and unspecified IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("192.0.2.1")},
				{Addr: netip.MustParseAddr("::")},
			},
			want: true,
		},
		{
			name: "unspecified IPv4 and valid IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("0.0.0.0")},
				{Addr: netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := &tables.Device{Name: "eth0", Index: 2, Addrs: tt.addrs}
			assert.Equal(t, tt.want, directRoutingDeviceHasAddr(dev))
		})
	}
}
