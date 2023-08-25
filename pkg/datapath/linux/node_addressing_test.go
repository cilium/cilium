// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestFilterLocalAddresses(t *testing.T) {
	tests := []struct {
		name         string
		addrs        []netlink.Addr
		ipsToExclude []net.IP
		addrScopeMax int
		want         []net.IP
	}{
		{
			name: "simple",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "multiple",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("10.0.0.2"),
			},
		},
		{
			name: "scopeMaxLink",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_LINK),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.3")},
					Scope: int(netlink.SCOPE_NOWHERE),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_LINK),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "scopeMaxHost",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_LINK),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.3")},
					Scope: int(netlink.SCOPE_NOWHERE),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("10.0.0.2"),
			},
		},
		{
			name: "scopeMaxNowhere",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_LINK),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.3")},
					Scope: int(netlink.SCOPE_NOWHERE),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_NOWHERE),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("10.0.0.2"),
				net.ParseIP("10.0.0.3"),
			},
		},
		{
			name: "exclude",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{
				net.ParseIP("10.0.0.2"),
			},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "excludeMultiple",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.3")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{
				net.ParseIP("10.0.0.2"),
				net.ParseIP("10.0.0.3"),
			},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "ipv6 simple",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("2001:db8::"),
			},
		},
		{
			name: "ipv6 multiple",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("2600:beef::")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("2001:db8::"),
				net.ParseIP("2600:beef::"),
			},
		},
		{
			name: "v4/v6 mix",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("2001:db8::"),
			},
		},
		{
			name: "v6 exclude",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{
				net.ParseIP("2001:db8::"),
			},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "include link-local v4",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("169.254.20.10")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("169.254.169.254")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("169.254.20.10"),
				net.ParseIP("169.254.169.254"),
			},
		},
		{
			name: "include link-local v6",
			addrs: []netlink.Addr{
				{
					IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("fe80::")},
					Scope: int(netlink.SCOPE_HOST),
				},
				{
					IPNet: &net.IPNet{IP: net.ParseIP("fe80::1234")},
					Scope: int(netlink.SCOPE_HOST),
				},
			},
			ipsToExclude: []net.IP{},
			addrScopeMax: int(netlink.SCOPE_HOST),
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("fe80::"),
				net.ParseIP("fe80::1234"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterLocalAddresses(tt.addrs, tt.ipsToExclude, tt.addrScopeMax)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterLocalAddresses(): got = %v, want = %v", got, tt.want)
			}
		})
	}
}
