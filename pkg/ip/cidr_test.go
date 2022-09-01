// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

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

func TestIPNetToPrefix(t *testing.T) {
	_, v4IPNet, err := net.ParseCIDR("1.1.1.1/32")
	assert.NoError(t, err)
	_, v6IPNet, err := net.ParseCIDR("::ff/128")
	assert.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix(v4IPNet.String()), IPNetToPrefix(v4IPNet))
	assert.Equal(t, netip.MustParsePrefix(v6IPNet.String()), IPNetToPrefix(v6IPNet))

	assert.Equal(t, netip.Prefix{}, IPNetToPrefix(nil))
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
