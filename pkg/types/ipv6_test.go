// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

var testIPv6Address IPv6 = [16]byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}

func TestIPv6(t *testing.T) {
	var expectedAddress net.IP = []byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}
	result := testIPv6Address.IP()

	require.Equal(t, expectedAddress, result)
}

func TestAddrV6(t *testing.T) {
	expectedAddress := netip.AddrFrom16(testIPv6Address)
	result := testIPv6Address.Addr()

	require.Equal(t, expectedAddress, result)
}

func TestStringV6(t *testing.T) {
	expectedStr := "f00d::ac10:14:0:1"
	result := testIPv6Address.String()

	require.Equal(t, expectedStr, result)
}
