// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPRangeToIPNet(t *testing.T) {
	assert.Equal(t, net.IPNet{
		IP:   net.ParseIP("192.168.1.0"),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}, ipRangeToIPNet(
		net.ParseIP("192.168.1.0"),
		net.ParseIP("192.168.1.255"),
	))

	assert.Equal(t, net.IPNet{
		IP:   net.ParseIP("192.168.1.0"),
		Mask: net.IPv4Mask(255, 255, 255, 128),
	}, ipRangeToIPNet(
		net.ParseIP("192.168.1.0"),
		net.ParseIP("192.168.1.127"),
	))

	assert.Equal(t, net.IPNet{
		IP:   net.ParseIP("192.168.1.128"),
		Mask: net.IPv4Mask(255, 255, 255, 128),
	}, ipRangeToIPNet(
		net.ParseIP("192.168.1.128"),
		net.ParseIP("192.168.1.255"),
	))

	// While technically incorrect, its the best guess since start and stop only
	// share 192.168.1 as prefix so the closest CIDR is 192.168.1.0/24
	assert.Equal(t, net.IPNet{
		IP:   net.ParseIP("192.168.1.100"),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}, ipRangeToIPNet(
		net.ParseIP("192.168.1.100"),
		net.ParseIP("192.168.1.200"),
	))
}
