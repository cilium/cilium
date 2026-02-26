// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptional(t *testing.T) {
	o1 := Some(42)
	v1, ok := o1.Get()
	require.True(t, ok)
	require.Equal(t, 42, v1)

	o2 := None[uint32]()
	v2, ok := o2.Get()
	require.False(t, ok)
	require.Equal(t, uint32(0), v2)
}
