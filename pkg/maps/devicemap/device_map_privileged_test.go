// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) *DeviceMap {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)

	deviceMap := newMap()
	err = deviceMap.init()
	require.NoError(tb, err)

	tb.Cleanup(func() {
		err := deviceMap.close()
		require.NoError(tb, err)
	})

	return deviceMap
}

func TestPrivilegedDeviceMap(t *testing.T) {
	deviceMap := setup(t)

	randMAC01, _ := mac.GenerateRandMAC()
	mac01, err := randMAC01.Uint64()
	require.NoError(t, err)
	randMAC02, _ := mac.GenerateRandMAC()
	mac02, err := randMAC02.Uint64()
	require.NoError(t, err)
	ifIndex := uint32(10)
	key := DeviceKey{IfIndex: ifIndex}
	val01 := DeviceValue{MAC: mac01, L3: uint8(0)}
	val02 := DeviceValue{MAC: mac02, L3: uint8(1)}

	value, err := deviceMap.Lookup(&key)
	require.Error(t, err)
	require.Nil(t, value)

	err = deviceMap.Update(&key, &val01)
	require.NoError(t, err)

	value, err = deviceMap.Lookup(&key)
	dv := value.(*DeviceValue)
	require.NoError(t, err)
	require.Equal(t, mac01, dv.MAC)
	require.Equal(t, uint8(0), dv.L3)

	err = deviceMap.Update(&key, &val02)
	require.NoError(t, err)

	value, err = deviceMap.Lookup(&key)
	dv = value.(*DeviceValue)
	require.NoError(t, err)
	require.Equal(t, mac02, dv.MAC)
	require.Equal(t, uint8(1), dv.L3)

	err = deviceMap.Delete(&key)
	require.NoError(t, err)

	value, err = deviceMap.Lookup(&key)
	require.Error(t, err)
	require.Nil(t, value)
}
