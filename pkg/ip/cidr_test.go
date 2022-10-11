// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefixToIPNet(t *testing.T) {
	_, v4IPNet, err := net.ParseCIDR("1.1.1.1/32")
	assert.NoError(t, err)
	_, v6IPNet, err := net.ParseCIDR("::ff/128")
	assert.NoError(t, err)
	assert.Equal(t, v4IPNet, PrefixToIPNet(netip.MustParsePrefix("1.1.1.1/32")))
	assert.Equal(t, v6IPNet, PrefixToIPNet(netip.MustParsePrefix("::ff/128")))

	var nilNet *net.IPNet
	assert.Equal(t, nilNet, PrefixToIPNet(netip.Prefix{}))
}

func TestAddrToIPNet(t *testing.T) {
	_, v4IPNet, err := net.ParseCIDR("1.1.1.1/32")
	assert.NoError(t, err)
	_, v6IPNet, err := net.ParseCIDR("::ff/128")
	assert.NoError(t, err)

	ip4 := netip.MustParseAddr("1.1.1.1")
	assert.NoError(t, err)
	assert.Equal(t, v4IPNet, AddrToIPNet(ip4))

	ip6 := netip.MustParseAddr("::ff")
	assert.NoError(t, err)
	assert.Equal(t, v6IPNet, AddrToIPNet(ip6))

	var nilNet *net.IPNet
	assert.Equal(t, nilNet, AddrToIPNet(netip.Addr{}))
}

func TestIPToNetPrefix(t *testing.T) {
	v4, _, err := net.ParseCIDR("1.1.1.1/32")
	assert.NoError(t, err)
	v6, _, err := net.ParseCIDR("::ff/128")
	assert.NoError(t, err)
	assert.Equal(t, netip.PrefixFrom(netip.MustParseAddr(v4.String()), 32), IPToNetPrefix(v4.To4()))
	assert.Equal(t, netip.PrefixFrom(netip.MustParseAddr(v6.String()), 128), IPToNetPrefix(v6.To16()))

	assert.Equal(t, netip.Prefix{}, IPToNetPrefix(nil))
}

func mustParseCIDR(t *testing.T, s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	assert.NoError(t, err)
	return n
}

func TestNetsContainsAny(t *testing.T) {
	tests := []struct {
		name string
		a    []*net.IPNet
		b    []*net.IPNet
		ret  bool
	}{
		{
			name: "a contains b",
			a:    []*net.IPNet{mustParseCIDR(t, "0.0.0.0/0")},
			b:    []*net.IPNet{mustParseCIDR(t, "192.0.0.1/32")},
			ret:  true,
		},
		{
			name: "b contains a",
			a:    []*net.IPNet{mustParseCIDR(t, "192.0.0.1/32")},
			b:    []*net.IPNet{mustParseCIDR(t, "0.0.0.0/0")},
		},
		{
			name: "a equals b",
			a:    []*net.IPNet{mustParseCIDR(t, "192.0.0.1/32")},
			b:    []*net.IPNet{mustParseCIDR(t, "192.0.0.1/32")},
			ret:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.ret, NetsContainsAny(tt.a, tt.b))
		})
	}
}
