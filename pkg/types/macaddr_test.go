// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

var testMACAddress MACAddr = [6]byte{1, 2, 3, 4, 5, 6}

func TestHardwareAddr(t *testing.T) {
	var expectedAddress net.HardwareAddr = []byte{1, 2, 3, 4, 5, 6}
	result := testMACAddress.hardwareAddr()

	require.Equal(t, expectedAddress, result)
}

func TestStringMAC(t *testing.T) {
	expectedStr := "01:02:03:04:05:06"
	result := testMACAddress.String()

	require.Equal(t, expectedStr, result)
}
