// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netdev

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

func setup(tb testing.TB) {
	tb.Helper()
	testutils.PrivilegedTest(tb)
	logger := hivetest.Logger(tb)

	bpf.CheckOrMountFS(logger, "")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")
}

func TestNewDeviceState(t *testing.T) {
	t.Run("mac copied and l3 unset for valid length", func(t *testing.T) {
		mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		state := NewDeviceState(mac)

		require.False(t, state.IsL3())
		require.Equal(t, types.MACAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, state.MAC)
	})

	t.Run("l3 set when mac length invalid", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee}
		state := NewDeviceState(mac)

		require.True(t, state.IsL3())
		require.Equal(t, types.MACAddr{}, state.MAC)
	})
}

func TestPrivilegedNetDevMap(t *testing.T) {
	setup(t)

	dm := newNetDevMap()
	require.NoError(t, dm.Map.CreateUnpinned())

	t.Cleanup(func() {
		require.NoError(t, dm.close())
	})

	state1 := NewDeviceState(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	state2 := NewDeviceState(net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})

	require.NoError(t, dm.Upsert(1, state1))
	require.NoError(t, dm.Upsert(2, state2))

	got1, err := dm.Lookup(1)
	require.NoError(t, err)
	require.Equal(t, state1, *got1)

	got2, err := dm.Lookup(2)
	require.NoError(t, err)
	require.Equal(t, state2, *got2)

	seen := map[uint32]DeviceState{}
	require.NoError(t, dm.IterateWithCallback(func(k *Index, v *DeviceState) {
		if uint32(*k) == 1 || uint32(*k) == 2 {
			seen[uint32(*k)] = *v
		}
	}))
	require.Len(t, seen, 2)
	require.Equal(t, state1, seen[1])
	require.Equal(t, state2, seen[2])

	require.NoError(t, dm.Clear(2))
	got2, err = dm.Lookup(2)
	require.NoError(t, err)
	require.Equal(t, DeviceState{}, *got2)
}
