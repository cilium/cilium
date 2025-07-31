// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestDeviceMap(t *testing.T) {
	setup(t)
	deviceMap := newMap(hivetest.Logger(t))
	err := deviceMap.init()
	require.NoError(t, err)
	defer deviceMap.bpfMap.Unpin()

	randMAC01, _ := mac.GenerateRandMAC()
	mac01, err := randMAC01.Uint64()
	require.NoError(t, err)
	randMAC02, _ := mac.GenerateRandMAC()
	mac02, err := randMAC02.Uint64()
	require.NoError(t, err)
	ifIndex := uint32(10)

	_, err = deviceMap.Lookup(ifIndex)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)

	err = deviceMap.Update(ifIndex, mac01, 0)
	require.NoError(t, err)

	info, err := deviceMap.Lookup(ifIndex)
	require.NoError(t, err)
	require.Equal(t, mac01, info.MAC)
	require.Equal(t, uint8(0), info.L3)

	err = deviceMap.Update(ifIndex, mac02, 1)
	require.NoError(t, err)

	info, err = deviceMap.Lookup(ifIndex)
	require.NoError(t, err)
	require.Equal(t, mac02, info.MAC)
	require.Equal(t, uint8(1), info.L3)

	err = deviceMap.Delete(ifIndex)
	require.NoError(t, err)

	_, err = deviceMap.Lookup(ifIndex)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
