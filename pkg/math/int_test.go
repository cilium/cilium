// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package math

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	maxIntValue = int(^uint(0) >> 1)
	minIntValue = -maxIntValue - 1
)

func TestIntMin(t *testing.T) {
	require.Equal(t, 10, IntMin(10, 20))
	require.Equal(t, 10, IntMin(20, 10))
	require.Equal(t, 10, IntMin(10, 10))
	require.Equal(t, IntMin(-10, 10), -10)
	require.Equal(t, 0, IntMin(0, 10))
	require.Equal(t, minIntValue, IntMin(minIntValue, maxIntValue))
}

func TestIntMax(t *testing.T) {
	require.Equal(t, 20, IntMax(10, 20))
	require.Equal(t, 20, IntMax(20, 10))
	require.Equal(t, 10, IntMax(10, 10))
	require.Equal(t, 10, IntMax(-10, 10))
	require.Equal(t, 10, IntMax(0, 10))
	require.Equal(t, maxIntValue, IntMax(minIntValue, maxIntValue))
}
