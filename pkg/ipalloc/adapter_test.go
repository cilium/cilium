// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPRangeToIPNet(t *testing.T) {
	assert.Equal(t,
		netip.MustParsePrefix("192.168.1.0/24"),
		ipRangeToPrefix(
			netip.MustParseAddr("192.168.1.0"),
			netip.MustParseAddr("192.168.1.255"),
		))

	assert.Equal(t,
		netip.MustParsePrefix("192.168.1.0/25"),
		ipRangeToPrefix(
			netip.MustParseAddr("192.168.1.0"),
			netip.MustParseAddr("192.168.1.127"),
		))

	assert.Equal(t,
		netip.MustParsePrefix("192.168.1.128/25"),
		ipRangeToPrefix(
			netip.MustParseAddr("192.168.1.128"),
			netip.MustParseAddr("192.168.1.255"),
		))

	assert.Equal(t,
		netip.Prefix{},
		ipRangeToPrefix(
			netip.MustParseAddr("192.168.1.100"),
			netip.MustParseAddr("192.168.1.200"),
		))
}
