// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicesmap

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
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

		require.Equal(t, uint8(0), state.L3)
		require.Equal(t, types.MACAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, state.MAC)
	})

	t.Run("l3 set when mac length invalid", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee}
		state := NewDeviceState(mac)

		require.Equal(t, uint8(1), state.L3)
		require.Equal(t, types.MACAddr{}, state.MAC)
	})
}

func TestPrivilegedDevicesMap(t *testing.T) {
	setup(t)
	logger := hivetest.Logger(t)

	dm := NewMap(hivetest.Lifecycle(t), logger)
	mapImpl, ok := dm.(*devicesMap)
	require.True(t, ok, "expected devicesMap implementation")
	require.NotNil(t, mapImpl.Map)

	t.Cleanup(func() {
		require.NoError(t, mapImpl.Map.Close())
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
	require.NoError(t, dm.IterateWithCallback(func(k *DeviceKey, v *DeviceState) {
		seen[k.IfIndex] = *v
	}))
	require.Len(t, seen, 2)
	require.Equal(t, state1, seen[1])
	require.Equal(t, state2, seen[2])

	require.NoError(t, dm.Delete(2))
	_, err = dm.Lookup(2)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
