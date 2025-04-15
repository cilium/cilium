// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPToNetPrefix(t *testing.T) {
	v4, _, err := net.ParseCIDR("1.1.1.1/32")
	assert.NoError(t, err)
	v6, _, err := net.ParseCIDR("::ff/128")
	assert.NoError(t, err)
	assert.Equal(t, netip.PrefixFrom(netip.MustParseAddr(v4.String()), 32), IPToNetPrefix(v4.To4()))
	assert.Equal(t, netip.PrefixFrom(netip.MustParseAddr(v6.String()), 128), IPToNetPrefix(v6.To16()))

	assert.Equal(t, netip.Prefix{}, IPToNetPrefix(nil))
}

func TestPrefixesContains(t *testing.T) {
	tests := []struct {
		prefixes []netip.Prefix
		addr     netip.Addr
		ret      bool
	}{
		{
			prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			addr:     netip.MustParseAddr("192.0.0.1"),
			ret:      true,
		},
		{
			prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			addr:     netip.MustParseAddr("192.0.0.1"),
			ret:      true,
		},
		{
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.0.1/32"), netip.MustParsePrefix("f00d::/118")},
			addr:     netip.MustParseAddr("f00d::1"),
			ret:      true,
		},
		{
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.0.1/32")},
			addr:     netip.MustParseAddr("0.0.0.0"),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("contains(%v, %s)", tt.prefixes, tt.addr), func(t *testing.T) {
			assert.Equal(t, tt.ret, PrefixesContains(tt.prefixes, tt.addr))
		})
	}
}
