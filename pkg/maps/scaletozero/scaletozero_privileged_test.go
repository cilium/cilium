// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"context"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	echo = loadbalancer.NewServiceName("test", "echo")
	pg   = loadbalancer.NewServiceName("test", "pg")
)

func setup(tb testing.TB) Map {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	require.NoError(tb, rlimit.RemoveMemlock())

	var scaleToZeroMap Map
	h := hive.New(
		registry.Cell,
		cell.Provide(NewMap),
		cell.Invoke(func(m Map) {
			scaleToZeroMap = m
		}),
	)
	require.NoError(tb, h.Start(hivetest.Logger(tb), tb.Context()))
	tb.Cleanup(func() {
		// tb.Context() is already cancelled by the time cleanups run.
		require.NoError(tb, h.Stop(hivetest.Logger(tb), context.Background()))
	})

	return scaleToZeroMap
}

func dump(t *testing.T, m Map) map[loadbalancer.ServiceID]uint64 {
	t.Helper()

	entries := map[loadbalancer.ServiceID]uint64{}
	require.NoError(t, m.Dump(func(id loadbalancer.ServiceID, lastWake uint64) {
		entries[id] = lastWake
	}))

	return entries
}

func TestPrivilegedScaleToZeroMap(t *testing.T) {
	m := setup(t)

	require.Empty(t, dump(t, m))

	require.NoError(t, m.Track(1, echo))
	require.NoError(t, m.Track(4096, pg))
	require.Equal(t, map[loadbalancer.ServiceID]uint64{1: 0, 4096: 0}, dump(t, m))

	require.NoError(t, m.Untrack(1))
	require.Equal(t, map[loadbalancer.ServiceID]uint64{4096: 0}, dump(t, m))

	// Untracking a service that was never tracked is not an error, prune
	// and reconciliation both rely on that.
	require.NoError(t, m.Untrack(1))
	require.NoError(t, m.Untrack(1234))

	require.NoError(t, m.Untrack(4096))
	require.Empty(t, dump(t, m))
}

// TestPrivilegedScaleToZeroMapResolve covers what the demand tracker needs:
// every ID that was tracked resolves back to the service it was tracked for,
// including the several IDs a node-address expansion tracks under one name.
func TestPrivilegedScaleToZeroMapResolve(t *testing.T) {
	m := setup(t)

	_, found := m.Resolve(1)
	require.False(t, found, "an untracked ID resolves to nothing")

	require.NoError(t, m.Track(1, echo))
	require.NoError(t, m.Track(2, echo))
	require.NoError(t, m.Track(3, pg))

	for id, want := range map[loadbalancer.ServiceID]loadbalancer.ServiceName{1: echo, 2: echo, 3: pg} {
		name, found := m.Resolve(id)
		require.True(t, found, "ID %d", id)
		require.Equal(t, want, name, "ID %d", id)
	}

	// Re-tracking an entry the datapath already stamped, as happens after an
	// agent restart, still records the name.
	require.NoError(t, m.Track(3, pg))
	name, found := m.Resolve(3)
	require.True(t, found)
	require.Equal(t, pg, name)

	require.NoError(t, m.Untrack(1))
	_, found = m.Resolve(1)
	require.False(t, found, "untracking drops the name")

	require.NoError(t, m.Untrack(2))
	require.NoError(t, m.Untrack(3))
}

// TestPrivilegedScaleToZeroMapKeepsWakeStamp covers the contract the datapath
// depends on: re-tracking a service must not reset the rate limiter stamp it
// left in the entry.
func TestPrivilegedScaleToZeroMapKeepsWakeStamp(t *testing.T) {
	m := setup(t)

	const id = loadbalancer.ServiceID(7)
	require.NoError(t, m.Track(id, echo))

	stamp := uint64(1234567890)
	require.NoError(t, m.(*scaleToZeroMap).m.Update(serviceKey(id), stamp, ciliumebpf.UpdateExist))

	require.NoError(t, m.Track(id, echo))
	require.Equal(t, map[loadbalancer.ServiceID]uint64{id: stamp}, dump(t, m))

	require.NoError(t, m.Untrack(id))
}
