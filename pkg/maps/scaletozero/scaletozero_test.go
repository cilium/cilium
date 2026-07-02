// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestKeyValue(t *testing.T) {
	k := &Key{SvcID: byteorder.HostToNetwork16(42)}
	require.Equal(t, "42", k.String())

	v := &Value{LastEmitNs: 99}
	require.Equal(t, "99", v.String())
}

func newRawMap() *scaleToZeroMap {
	return &scaleToZeroMap{
		m:     bpf.NewMap(MapName, ebpf.Hash, &Key{}, &Value{}, 16, unix.BPF_F_NO_PREALLOC),
		names: map[loadbalancer.ServiceID]loadbalancer.ServiceName{},
	}
}

func TestMapMetadata(t *testing.T) {
	m := newRawMap().m
	require.Equal(t, MapName, m.Name())
	require.Equal(t, ebpf.Hash, m.Type())
	require.Equal(t, uint32(16), m.MaxEntries())
	require.Equal(t, uint32(4), m.KeySize())   // u16 svc_id + u16 pad
	require.Equal(t, uint32(8), m.ValueSize()) // u64 last_emit_ns
}

func TestPrivilegedScaleToZeroMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)
	bpf.CheckOrMountFS(logger, "")
	require.NoError(t, rlimit.RemoveMemlock())

	m := newRawMap()
	require.NoError(t, m.m.OpenOrCreate())
	t.Cleanup(func() { require.NoError(t, m.m.Close()) })
	require.FileExists(t, bpf.MapPath(logger, MapName))

	const svc = 7
	name := loadbalancer.NewServiceName("ns", "echo")
	key := &Key{SvcID: byteorder.HostToNetwork16(svc)}

	// EnsureTracked inserts a zero-timestamp entry and records the name.
	require.NoError(t, m.EnsureTracked(svc, name))
	v, err := m.m.Lookup(key)
	require.NoError(t, err)
	require.Equal(t, uint64(0), v.(*Value).LastEmitNs)
	require.Equal(t, name, m.Tracked()[svc])

	// A subsequent EnsureTracked must not clobber an existing timestamp.
	require.NoError(t, m.m.Update(key, &Value{LastEmitNs: 123456}))
	require.NoError(t, m.EnsureTracked(svc, name))
	v, err = m.m.Lookup(key)
	require.NoError(t, err)
	require.Equal(t, uint64(123456), v.(*Value).LastEmitNs)

	// Delete removes the entry and the name; deleting a missing entry is fine.
	require.NoError(t, m.Delete(svc))
	_, err = m.m.Lookup(key)
	require.Error(t, err)
	require.NotContains(t, m.Tracked(), loadbalancer.ServiceID(svc))
	require.NoError(t, m.Delete(svc))
}

func TestPrivilegedScaleToZeroPrune(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)
	bpf.CheckOrMountFS(logger, "")
	require.NoError(t, rlimit.RemoveMemlock())

	m := newRawMap()
	require.NoError(t, m.m.OpenOrCreate())
	t.Cleanup(func() { require.NoError(t, m.m.Close()) })

	name := loadbalancer.NewServiceName("ns", "svc")
	for _, id := range []loadbalancer.ServiceID{1, 2, 3} {
		require.NoError(t, m.EnsureTracked(id, name))
	}

	// Keep ids 1 and 3; 2 is an orphan.
	keep := map[loadbalancer.ServiceID]bool{1: true, 3: true}
	require.NoError(t, m.Prune(func(id loadbalancer.ServiceID) bool { return keep[id] }))

	for _, id := range []loadbalancer.ServiceID{1, 3} {
		_, err := m.m.Lookup(&Key{SvcID: byteorder.HostToNetwork16(uint16(id))})
		require.NoError(t, err, "kept id %d must remain", id)
		require.Contains(t, m.Tracked(), id)
	}
	_, err := m.m.Lookup(&Key{SvcID: byteorder.HostToNetwork16(2)})
	require.Error(t, err, "orphan id 2 must be pruned from the BPF map")
	require.NotContains(t, m.Tracked(), loadbalancer.ServiceID(2))
}

// TestTracked exercises the in-memory svc_id -> name registry without a
// kernel. Several ids may map to the same service, as NodePort services expand
// into one datapath id per node address.
func TestTracked(t *testing.T) {
	m := &scaleToZeroMap{names: map[loadbalancer.ServiceID]loadbalancer.ServiceName{}}
	echo := loadbalancer.NewServiceName("ns", "echo")

	require.Empty(t, m.Tracked())
	m.trackName(8, echo)  // ClusterIP id
	m.trackName(11, echo) // expanded NodePort id
	tr := m.Tracked()
	require.Equal(t, echo, tr[8])
	require.Equal(t, echo, tr[11])

	m.untrackName(11)
	require.NotContains(t, m.Tracked(), loadbalancer.ServiceID(11))
	require.Equal(t, echo, m.Tracked()[8])
}
