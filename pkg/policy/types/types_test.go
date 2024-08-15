// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyMask(t *testing.T) {
	key := NewKey(0, 0, 0, 0, 0)
	require.Equal(t, uint8(0), key.TrafficDirection)
	require.Equal(t, uint8(0), key.PortPrefixLen())
	require.Equal(t, uint16(0), key.PortMask())
}
