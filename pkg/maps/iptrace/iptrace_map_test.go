// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptrace

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
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
	lc := cell.NewDefaultLifecycle(nil, 0, 0)
	reg, err := registry.NewMapSpecRegistry(lc)
	require.NoError(t, err)
	mOut := NewMap(lc, reg)
	m := mOut.Map
	err = lc.Start(hivetest.Logger(t), t.Context())

	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, MapName, m.Name())
	require.Equal(t, ebpf.PerCPUArray, m.Type())
	require.Equal(t, uint32(1), m.MaxEntries())
	require.Equal(t, uint32(0), m.Flags())
	require.Equal(t, uint32(4), m.KeySize())
	require.Equal(t, uint32(8), m.ValueSize())
}
