// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iana

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsSvcName(t *testing.T) {
	require.Equal(t, IsSvcName(""), false)                 // Too short
	require.Equal(t, IsSvcName("1234567890abcdef"), false) // Too long
	require.Equal(t, IsSvcName("1"), false)                // Missing letter
	require.Equal(t, IsSvcName("1a"), true)
	require.Equal(t, IsSvcName("Z"), true)
	require.Equal(t, IsSvcName("a9"), true)
	require.Equal(t, IsSvcName("a-9"), true)
	require.Equal(t, IsSvcName("a--9"), false) // Two consecutive dashes
	require.Equal(t, IsSvcName("-a9"), false)  // Begins with a dash
	require.Equal(t, IsSvcName("a9-"), false)  // Ends with a dash
	require.Equal(t, IsSvcName("a-b9-1"), true)
	require.Equal(t, IsSvcName("1-a-9"), true)
	require.Equal(t, IsSvcName("a-b-c-d-e-f"), true)
	require.Equal(t, IsSvcName("1-2-3-4"), false) // No letter(s)
}
