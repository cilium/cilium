// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWaitUntil(t *testing.T) {
	require.Error(t, WaitUntil(func() bool { return false }, 50*time.Millisecond))
	require.NoError(t, WaitUntil(func() bool { return true }, 50*time.Millisecond))

	counter := 0
	countTo5 := func() bool {
		if counter > 5 {
			return true
		}
		counter++
		return false
	}

	require.Error(t, WaitUntil(countTo5, 1*time.Millisecond))

	counter = 0
	require.NoError(t, WaitUntil(countTo5, time.Second))
}
