// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iana

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsSvcName(t *testing.T) {
	require.False(t, IsSvcName(""))                 // Too short
	require.False(t, IsSvcName("1234567890abcdef")) // Too long
	require.False(t, IsSvcName("1"))                // Missing letter
	require.True(t, IsSvcName("1a"))
	require.True(t, IsSvcName("Z"))
	require.True(t, IsSvcName("a9"))
	require.True(t, IsSvcName("a-9"))
	require.False(t, IsSvcName("a--9")) // Two consecutive dashes
	require.False(t, IsSvcName("-a9"))  // Begins with a dash
	require.False(t, IsSvcName("a9-"))  // Ends with a dash
	require.True(t, IsSvcName("a-b9-1"))
	require.True(t, IsSvcName("1-a-9"))
	require.True(t, IsSvcName("a-b-c-d-e-f"))
	require.False(t, IsSvcName("1-2-3-4")) // No letter(s)
}
