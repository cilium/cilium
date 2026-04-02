// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewNodeAddressing(t *testing.T) {
	fna := NewAddressing()

	require.NotNil(t, fna.IPv6().Router())
	require.NotNil(t, fna.IPv4().Router())
	require.NotNil(t, fna.IPv4().AllocationCIDR())
}
