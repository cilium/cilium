// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// TestFakeScaleToZeroMap covers the parts of the real map's contract that
// tests of its consumers rely on.
func TestFakeScaleToZeroMap(t *testing.T) {
	m := NewFakeScaleToZeroMap()
	echo := loadbalancer.NewServiceName("test", "echo")

	require.NoError(t, m.Track(1, echo))
	m.Wake(1, 1234567890)

	name, found := m.Resolve(1)
	require.True(t, found)
	require.Equal(t, echo, name)

	// Re-tracking keeps the datapath's stamp.
	require.NoError(t, m.Track(1, echo))
	require.Equal(t, map[loadbalancer.ServiceID]uint64{1: 1234567890}, m.Entries())

	// Waking an untracked service does not track it.
	m.Wake(2, 1234567890)
	require.NotContains(t, m.Entries(), loadbalancer.ServiceID(2))

	_, found = m.Resolve(2)
	require.False(t, found)

	require.NoError(t, m.Untrack(1))
	require.NoError(t, m.Untrack(1))
	require.Empty(t, m.Entries())

	_, found = m.Resolve(1)
	require.False(t, found, "untracking drops the name")
}
