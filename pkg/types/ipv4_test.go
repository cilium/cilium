// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

var testIPv4Address IPv4 = [4]byte{10, 0, 0, 2}

func TestIP(t *testing.T) {
	var expectedAddress net.IP = []byte{10, 0, 0, 2}
	result := testIPv4Address.IP()

	require.Equal(t, expectedAddress, result)
}

func TestAddr(t *testing.T) {
	expectedAddress := netip.MustParseAddr("10.0.0.2")
	result := testIPv4Address.Addr()

	require.Equal(t, expectedAddress, result)
}

func TestString(t *testing.T) {
	expectedStr := "10.0.0.2"
	result := testIPv4Address.String()

	require.Equal(t, expectedStr, result)
}
