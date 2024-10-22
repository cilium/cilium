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
	require.Equal(t, IntMin(10, 20), 10)
	require.Equal(t, IntMin(20, 10), 10)
	require.Equal(t, IntMin(10, 10), 10)
	require.Equal(t, IntMin(-10, 10), -10)
	require.Equal(t, IntMin(0, 10), 0)
	require.Equal(t, IntMin(minIntValue, maxIntValue), minIntValue)
}

func TestIntMax(t *testing.T) {
	require.Equal(t, IntMax(10, 20), 20)
	require.Equal(t, IntMax(20, 10), 20)
	require.Equal(t, IntMax(10, 10), 10)
	require.Equal(t, IntMax(-10, 10), 10)
	require.Equal(t, IntMax(0, 10), 10)
	require.Equal(t, IntMax(minIntValue, maxIntValue), maxIntValue)
}
