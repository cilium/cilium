// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Tests for the Device statedb table introduced in tables.go:
//
//	Device — primary key (Name), secondary indexes (Pool, Manager, PodUID, ClaimUID)
//
// Each test builds a minimal in-process statedb.DB (no Hive, no cluster) and
// exercises the table directly.

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestDB(t *testing.T) *statedb.DB {
	t.Helper()
	return statedb.New()
}

// ---------------------------------------------------------------------------
// Device table
// ---------------------------------------------------------------------------

const (
	tabTestPod1   = kube_types.UID("pod-1111")
	tabTestPod2   = kube_types.UID("pod-2222")
	tabTestClaim1 = kube_types.UID("claim-aaaa")
	tabTestClaim2 = kube_types.UID("claim-bbbb")
)

func TestDeviceTable(t *testing.T) {
	db := newTestDB(t)
	tbl, err := NewDeviceTable(db)
	require.NoError(t, err)

	rows := []*Device{
		{Name: "eth0", Manager: types.DeviceManagerTypeMock, Pool: "pool-a", Status: reconciler.StatusDone(), PodUID: tabTestPod1, ClaimUID: tabTestClaim1},
		{Name: "eth1", Manager: types.DeviceManagerTypeMock, Pool: "pool-b", Status: reconciler.StatusDone(), PodUID: tabTestPod1, ClaimUID: tabTestClaim2},
		{Name: "dummy0", Manager: types.DeviceManagerTypeDummy, Pool: "pool-a", Status: reconciler.StatusDone(), PodUID: tabTestPod2, ClaimUID: tabTestClaim1},
		{Name: "unalloc", Manager: types.DeviceManagerTypeMock, Pool: "pool-a", Status: reconciler.StatusDone()},
	}

	txn := db.WriteTxn(tbl)
	for _, r := range rows {
		tbl.Insert(txn, r)
	}
	txn.Commit()

	rtxn := db.ReadTxn()

	t.Run("primary key lookup", func(t *testing.T) {
		got, _, ok := tbl.Get(rtxn, DeviceByName("eth0"))
		require.True(t, ok)
		require.Equal(t, "pool-a", got.Pool)
	})

	t.Run("missing primary key returns false", func(t *testing.T) {
		_, _, ok := tbl.Get(rtxn, DeviceByName("nonexistent"))
		require.False(t, ok)
	})

	t.Run("pool secondary index — pool-a has three entries", func(t *testing.T) {
		var found []string
		for obj := range tbl.List(rtxn, DeviceByPool("pool-a")) {
			found = append(found, obj.Name)
		}
		require.ElementsMatch(t, []string{"eth0", "dummy0", "unalloc"}, found)
	})

	t.Run("manager secondary index — mock has three entries", func(t *testing.T) {
		var found []string
		for obj := range tbl.List(rtxn, DeviceByManager(types.DeviceManagerTypeMock)) {
			found = append(found, obj.Name)
		}
		require.ElementsMatch(t, []string{"eth0", "eth1", "unalloc"}, found)
	})

	t.Run("manager secondary index — dummy has one entry", func(t *testing.T) {
		var found []string
		for obj := range tbl.List(rtxn, DeviceByManager(types.DeviceManagerTypeDummy)) {
			found = append(found, obj.Name)
		}
		require.ElementsMatch(t, []string{"dummy0"}, found)
	})

	t.Run("pod secondary index — pod1 has two entries", func(t *testing.T) {
		var found []string
		for obj := range tbl.List(rtxn, DeviceByPodUID(tabTestPod1)) {
			found = append(found, obj.Name)
		}
		require.ElementsMatch(t, []string{"eth0", "eth1"}, found)
	})

	t.Run("claim secondary index — claim1 has two entries (pod1 and pod2)", func(t *testing.T) {
		var found []string
		for obj := range tbl.List(rtxn, DeviceByClaimUID(tabTestClaim1)) {
			found = append(found, obj.Name)
		}
		require.ElementsMatch(t, []string{"eth0", "dummy0"}, found)
	})

	t.Run("IsAllocated distinguishes allocated vs unallocated", func(t *testing.T) {
		got, _, ok := tbl.Get(rtxn, DeviceByName("unalloc"))
		require.True(t, ok)
		require.False(t, got.IsAllocated())

		got2, _, ok := tbl.Get(rtxn, DeviceByName("eth0"))
		require.True(t, ok)
		require.True(t, got2.IsAllocated())
	})

	t.Run("delete row", func(t *testing.T) {
		txn2 := db.WriteTxn(tbl)
		tbl.Delete(txn2, rows[0]) // delete eth0
		txn2.Commit()

		_, _, ok := tbl.Get(db.ReadTxn(), DeviceByName("eth0"))
		require.False(t, ok, "deleted row must not be found")
	})

	t.Run("clear allocation fields (unprepare semantics)", func(t *testing.T) {
		// Get current eth1 row.
		rtxn2 := db.ReadTxn()
		row, _, ok := tbl.Get(rtxn2, DeviceByName("eth1"))
		require.True(t, ok)
		require.True(t, row.IsAllocated())

		// Clear allocation fields in-place (unprepare pattern).
		txn3 := db.WriteTxn(tbl)
		cleared := row.Clone()
		cleared.PodUID = ""
		cleared.ClaimUID = ""
		cleared.Config = types.DeviceConfig{}
		tbl.Insert(txn3, cleared)
		txn3.Commit()

		rtxn3 := db.ReadTxn()
		got, _, ok := tbl.Get(rtxn3, DeviceByName("eth1"))
		require.True(t, ok, "row must still exist after clearing allocation")
		require.False(t, got.IsAllocated(), "row must be unallocated after clearing")
		require.Equal(t, "pool-b", got.Pool, "non-allocation fields must be preserved")
	})

	t.Run("delete one row, others intact", func(t *testing.T) {
		// eth0 was already deleted above; delete dummy0 now.
		rtxn2 := db.ReadTxn()
		row, _, ok := tbl.Get(rtxn2, DeviceByName("dummy0"))
		require.True(t, ok)

		txn4 := db.WriteTxn(tbl)
		tbl.Delete(txn4, row)
		txn4.Commit()

		rtxn4 := db.ReadTxn()
		_, _, ok = tbl.Get(rtxn4, DeviceByName("dummy0"))
		require.False(t, ok)

		// eth1 (now unallocated) and unalloc must still be present.
		_, _, ok = tbl.Get(rtxn4, DeviceByName("eth1"))
		require.True(t, ok)
		_, _, ok = tbl.Get(rtxn4, DeviceByName("unalloc"))
		require.True(t, ok)
	})
}
