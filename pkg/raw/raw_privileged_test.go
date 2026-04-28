// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package raw

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/crap"
	"github.com/cilium/cilium/pkg/testutils"
)

func countMapEntries(t *testing.T, m *crap.CrapMap) int {
	t.Helper()
	count := 0
	require.NoError(t, m.IterateWithCallback(func(k *crap.CrapKey, v *crap.CrapVal) {
		count++
	}))
	return count
}

func TestPrivilegedUpdateRawRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	logger := hivetest.Logger(t)
	bpf.CheckOrMountFS(logger, "")
	require.NoError(t, rlimit.RemoveMemlock())

	crapMap := crap.CreatePrivatePolicyMap(hivetest.Lifecycle(t), nil)

	existingKeepDst := netip.MustParseAddr("203.0.113.1")
	existingKeepPod := netip.MustParseAddr("10.0.0.1")
	staleDst := netip.MustParseAddr("203.0.113.2")
	stalePod := netip.MustParseAddr("10.0.0.2")
	newDst := netip.MustParseAddr("203.0.113.3")
	newPod := netip.MustParseAddr("10.0.0.3")

	manager := &CrapManager{
		logger: logger,
		bpfmap: crapMap,
	}

	// Seed the map with two entries before reconciliation.
	require.NoError(t, crapMap.Update(crap.NewKey(existingKeepDst), crap.NewVal(existingKeepPod)))
	require.NoError(t, crapMap.Update(crap.NewKey(staleDst), crap.NewVal(stalePod)))

	t.Run("keep, add, and remove", func(t *testing.T) {
		manager.updateRawRules(map[crap.CrapKey]crap.CrapVal{
			crap.NewKey(existingKeepDst): crap.NewVal(existingKeepPod),
			crap.NewKey(newDst):          crap.NewVal(newPod),
		})

		assert.Equal(t, 2, countMapEntries(t, crapMap))

		val, err := crapMap.Lookup(&crap.CrapKey{DestIP: crap.NewKey(existingKeepDst).DestIP})
		require.NoError(t, err)
		assert.True(t, val.Match(existingKeepPod))

		val, err = crapMap.Lookup(&crap.CrapKey{DestIP: crap.NewKey(newDst).DestIP})
		require.NoError(t, err)
		assert.True(t, val.Match(newPod))

		_, err = crapMap.Lookup(&crap.CrapKey{DestIP: crap.NewKey(staleDst).DestIP})
		assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	})

	t.Run("update existing entry value", func(t *testing.T) {
		updatedPod := netip.MustParseAddr("10.0.0.99")
		manager.updateRawRules(map[crap.CrapKey]crap.CrapVal{
			crap.NewKey(existingKeepDst): crap.NewVal(updatedPod),
		})

		assert.Equal(t, 1, countMapEntries(t, crapMap))

		val, err := crapMap.Lookup(&crap.CrapKey{DestIP: crap.NewKey(existingKeepDst).DestIP})
		require.NoError(t, err)
		assert.True(t, val.Match(updatedPod))
	})

	t.Run("empty desired clears all entries", func(t *testing.T) {
		manager.updateRawRules(map[crap.CrapKey]crap.CrapVal{})
		assert.Equal(t, 0, countMapEntries(t, crapMap))
	})
}
