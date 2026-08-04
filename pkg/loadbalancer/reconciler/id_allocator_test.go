// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestIDAllocatorMaxIDIsExclusive(t *testing.T) {
	firstID := loadbalancer.ServiceID(1)
	lastID := loadbalancer.ServiceID(3)
	maxID := lastID + 1

	alloc := newIDAllocator(firstID, maxID)

	// Allocate every ID in the known range of firstID .. lastID.
	for expectedID := firstID; expectedID <= lastID; expectedID++ {
		addr := loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			types.MustParseAddrCluster("10.0.0.1"),
			uint16(expectedID),
			loadbalancer.ScopeExternal,
		)

		id, err := alloc.acquireLocalID(addr)
		require.NoError(t, err)
		require.Equal(t, expectedID, id)
	}

	// Now verify we've exhausted the range. MaxID is the exclusive upper
	// bound so should never be allocated.
	addr := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.0.0.1"),
		uint16(maxID),
		loadbalancer.ScopeExternal,
	)
	id, err := alloc.acquireLocalID(addr)
	require.Zero(t, id)
	require.Error(t, err)
}
