// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyMask(t *testing.T) {
	key := NewKey(0, 0, 0, 0, 0)
	require.Equal(t, uint8(0), key.TrafficDirection())
	require.Equal(t, uint8(0), key.PortPrefixLen())
	require.Equal(t, uint16(0), key.DestPort)
	require.Equal(t, uint16(0xffff), key.EndPort())

	key = NewKey(1, 42, 6, 80, 16)
	require.Equal(t, uint8(1), key.TrafficDirection())
	require.Equal(t, uint32(42), key.Identity)
	require.Equal(t, uint8(16), key.PortPrefixLen())
	require.Equal(t, uint16(80), key.DestPort)
	require.Equal(t, uint16(80), key.EndPort())

	// for convenience in testing, 0 prefix len gets translated to 16 when port is non-zero
	key = NewKey(1, 42, 6, 80, 0)
	require.Equal(t, uint8(1), key.TrafficDirection())
	require.Equal(t, uint32(42), key.Identity)
	require.Equal(t, uint8(16), key.PortPrefixLen())
	require.Equal(t, uint16(80), key.DestPort)
	require.Equal(t, uint16(80), key.EndPort())

	key = NewKey(1, 42, 6, 80, 14)
	require.Equal(t, uint8(1), key.TrafficDirection())
	require.Equal(t, uint32(42), key.Identity)
	require.Equal(t, uint8(14), key.PortPrefixLen())
	require.Equal(t, uint16(80), key.DestPort)
	require.Equal(t, uint16(83), key.EndPort())
}
