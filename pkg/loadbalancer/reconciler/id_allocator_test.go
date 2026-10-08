// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func TestIDAllocatorMaxIDIsExclusive(t *testing.T) {
	firstID := loadbalancer.ServiceID(1)
	lastID := loadbalancer.ServiceID(3)
	maxID := lastID + 1

	alloc := newIDAllocator(firstID, maxID, idAllocatorMetrics{
		capacity:           metrics.NoOpGauge,
		allocations:        metrics.NoOpGauge,
		allocationAttempts: metrics.NoOpCounter,
		allocationFailures: metrics.NoOpCounter,
	})

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

func TestIDAllocatorMetrics(t *testing.T) {
	allocations := metric.NewGauge(metric.GaugeOpts{})
	capacity := metric.NewGauge(metric.GaugeOpts{})
	allocationAttempts := metric.NewCounter(metric.CounterOpts{})
	allocationFailures := metric.NewCounter(metric.CounterOpts{})
	metrics := idAllocatorMetrics{
		allocations:        allocations,
		capacity:           capacity,
		allocationAttempts: allocationAttempts,
		allocationFailures: allocationFailures,
	}

	// Verify a new allocator reports its capacity and starts empty without any
	// allocation attempts or failures.
	alloc := newIDAllocator(loadbalancer.ServiceID(1), loadbalancer.ServiceID(4), metrics)
	require.Zero(t, allocations.Get())
	require.Equal(t, float64(3), capacity.Get())
	require.Zero(t, allocationAttempts.Get())
	require.Zero(t, allocationFailures.Get())

	// Verify allocating an ID updates the gauge, while acquiring the same
	// address again does not count it twice.
	addr := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.0.0.1"),
		1,
		loadbalancer.ScopeExternal,
	)
	firstAllocatedID, err := alloc.acquireLocalID(addr)
	require.NoError(t, err)
	require.Equal(t, float64(1), allocations.Get())
	require.Equal(t, float64(1), allocationAttempts.Get())

	_, err = alloc.acquireLocalID(addr)
	require.NoError(t, err)
	require.Equal(t, float64(1), allocations.Get())
	require.Equal(t, float64(1), allocationAttempts.Get())

	// Verify adding a restored ID updates the gauge, but restoring the same
	// mapping again does not count it twice.
	restoredAddr := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.0.0.2"),
		2,
		loadbalancer.ScopeExternal,
	)
	restoredID := loadbalancer.ServiceID(2)

	alloc.addID(restoredAddr, restoredID)
	require.Equal(t, float64(2), allocations.Get())
	require.Equal(t, float64(1), allocationAttempts.Get())

	alloc.addID(restoredAddr, restoredID)
	require.Equal(t, float64(2), allocations.Get())

	// Fill the remaining allocation and verify all IDs are reported as used.
	thirdAddr := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.0.0.3"),
		3,
		loadbalancer.ScopeExternal,
	)
	thirdID, err := alloc.acquireLocalID(thirdAddr)
	require.NoError(t, err)
	require.Equal(t, float64(3), allocations.Get())
	require.Equal(t, float64(2), allocationAttempts.Get())
	require.Zero(t, allocationFailures.Get())

	// Verify an exhausted allocator records the failure without changing the
	// number of allocated IDs.
	exhaustedAddr := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.0.0.4"),
		4,
		loadbalancer.ScopeExternal,
	)
	failedID, err := alloc.acquireLocalID(exhaustedAddr)
	require.Zero(t, failedID)
	require.Error(t, err)
	require.Equal(t, float64(3), allocations.Get())
	require.Equal(t, float64(3), allocationAttempts.Get())
	require.Equal(t, float64(1), allocationFailures.Get())

	// Verify deleting IDs updates the gauge, while deleting an unknown ID doesn't.
	alloc.deleteLocalID(firstAllocatedID)
	require.Equal(t, float64(2), allocations.Get())

	alloc.deleteLocalID(firstAllocatedID)
	require.Equal(t, float64(2), allocations.Get())

	alloc.deleteLocalID(restoredID)
	require.Equal(t, float64(1), allocations.Get())

	alloc.deleteLocalID(thirdID)
	require.Zero(t, allocations.Get())

	// Recreating an allocator resets its gauges, but not cumulative counters.
	newIDAllocator(loadbalancer.ServiceID(1), loadbalancer.ServiceID(4), metrics)
	require.Zero(t, allocations.Get())
	require.Equal(t, float64(3), capacity.Get())
	require.Equal(t, float64(3), allocationAttempts.Get())
	require.Equal(t, float64(1), allocationFailures.Get())
}
