// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptrace

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)
	logger := hivetest.Logger(tb)

	bpf.CheckOrMountFS(logger, "")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")
}

func TestKey(t *testing.T) {
	k := Key(123)
	require.Equal(t, "123", k.String())

	nk := k.New()
	require.IsType(t, new(Key), nk)
	require.NotEqual(t, k, nk)
}

func TestTraceId(t *testing.T) {
	v := TraceId(456)
	require.Equal(t, "456", v.String())

	nv := v.New()
	require.IsType(t, new(TraceId), nv)
	require.NotEqual(t, v, nv)
}

func TestNewMap(t *testing.T) {
	m := NewMap()
	require.NotNil(t, m)
	require.Equal(t, MapName, m.Name())
	require.Equal(t, ebpf.PerCPUArray, m.Type())
	require.Equal(t, uint32(MaxEntries), m.MaxEntries())
	require.Equal(t, uint32(0), m.Flags())
	require.Equal(t, uint32(4), m.KeySize())
	require.Equal(t, uint32(8), m.ValueSize())
}

func TestPrivilegedIPTraceMap(t *testing.T) {
	setup(t)
	logger := hivetest.Logger(t)

	m := NewMap()
	require.NotNil(t, m, "Failed to initialize map")

	// Pinning a map requires it to be opened first.
	require.NoError(t, m.OpenOrCreate(), "Failed to create maps")
	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	require.FileExists(t, bpf.MapPath(logger, m.Name()), "Failed to create map")

	// Re-opening an existing map should not cause an error.
	m2 := NewMap()
	require.NotNil(t, m2, "Failed to initialize map")
	require.NoError(t, m2.OpenOrCreate(), "Failed to re-open map")
	require.NoError(t, m2.Close())
}
