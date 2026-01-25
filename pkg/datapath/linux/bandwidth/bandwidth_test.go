// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/node"
)

// TestEnsureHostEndpointQoS tests the lazy one-time setup of host endpoint
// with Guaranteed QoS priority.
func TestEnsureHostEndpointQoS(t *testing.T) {
	// Save the original endpoint ID to restore after tests
	originalEndpointID, _ := node.GetEndpointID()
	t.Cleanup(func() {
		node.SetEndpointID(originalEndpointID)
	})

	t.Run("skips setup when host endpoint not ready", func(t *testing.T) {
		// Set to template ID (host endpoint not created yet)
		node.SetEndpointID(0xffff)

		db, edtTable := setupTestDB(t)
		m := newTestManager(t, db, edtTable)

		// Call UpdateBandwidthLimit for a pod
		m.UpdateBandwidthLimit(100, 1000000, 0)

		// Verify host endpoint was NOT inserted (template ID should be skipped)
		txn := db.ReadTxn()
		_, _, found := edtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 0xffff,
			Direction:  DirectionEgress,
		}))
		assert.False(t, found, "Host endpoint with template ID should not be inserted")

		// Verify the pod entry was still inserted
		_, _, found = edtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 100,
			Direction:  DirectionEgress,
		}))
		assert.True(t, found, "Pod endpoint should be inserted")

		// Verify flag is still false (so we retry next time)
		assert.False(t, m.hostEpDone.Load(), "hostEpDone should be false when host EP not ready")
	})

	t.Run("sets up host endpoint when ready", func(t *testing.T) {
		// Set a real host endpoint ID
		node.SetEndpointID(42)

		db, edtTable := setupTestDB(t)
		m := newTestManager(t, db, edtTable)

		// Call UpdateBandwidthLimit for a pod
		m.UpdateBandwidthLimit(100, 1000000, 0)

		// Verify host endpoint was inserted with Guaranteed QoS
		txn := db.ReadTxn()
		hostEntry, _, found := edtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 42,
			Direction:  DirectionEgress,
		}))
		require.True(t, found, "Host endpoint should be inserted")
		assert.Equal(t, uint32(GuaranteedQoSDefaultPriority), hostEntry.Prio, "Host endpoint should have Guaranteed QoS priority")
		assert.Equal(t, uint64(0), hostEntry.BytesPerSecond, "Host endpoint should have no bandwidth limit")

		// Verify the pod entry was also inserted
		podEntry, _, found := edtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 100,
			Direction:  DirectionEgress,
		}))
		require.True(t, found, "Pod endpoint should be inserted")
		assert.Equal(t, uint64(1000000), podEntry.BytesPerSecond)

		// Verify flag is now true
		assert.True(t, m.hostEpDone.Load(), "hostEpDone should be true after setup")
	})

	t.Run("skips setup on subsequent calls (fast path)", func(t *testing.T) {
		// Set a real host endpoint ID
		node.SetEndpointID(42)

		db, edtTable := setupTestDB(t)
		m := newTestManager(t, db, edtTable)

		// First call - sets up host endpoint
		m.UpdateBandwidthLimit(100, 1000000, 0)
		assert.True(t, m.hostEpDone.Load(), "hostEpDone should be true after first call")

		// Manually delete the host endpoint entry to verify it's not re-added
		wtxn := db.WriteTxn(edtTable)
		hostEntry, _, found := edtTable.Get(wtxn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 42,
			Direction:  DirectionEgress,
		}))
		require.True(t, found)
		edtTable.Delete(wtxn, hostEntry)
		wtxn.Commit()

		// Verify host endpoint is deleted
		rtxn := db.ReadTxn()
		_, _, found = edtTable.Get(rtxn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 42,
			Direction:  DirectionEgress,
		}))
		assert.False(t, found, "Host endpoint should be deleted")

		// Second call - should skip host endpoint setup (flag is already true)
		m.UpdateBandwidthLimit(101, 2000000, 0)

		// Verify host endpoint is still NOT present (proves we skipped setup)
		rtxn2 := db.ReadTxn()
		_, _, found = edtTable.Get(rtxn2, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 42,
			Direction:  DirectionEgress,
		}))
		assert.False(t, found, "Host endpoint should NOT be re-added on subsequent calls")

		// Verify the second pod entry was inserted
		_, _, found = edtTable.Get(rtxn2, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 101,
			Direction:  DirectionEgress,
		}))
		assert.True(t, found, "Second pod endpoint should be inserted")
	})

	t.Run("retries setup after host endpoint becomes available", func(t *testing.T) {
		// Start with template ID
		node.SetEndpointID(0xffff)

		db, edtTable := setupTestDB(t)
		m := newTestManager(t, db, edtTable)

		// First call - host EP not ready, should skip
		m.UpdateBandwidthLimit(100, 1000000, 0)
		assert.False(t, m.hostEpDone.Load(), "hostEpDone should be false when host EP not ready")

		// Host endpoint becomes available
		node.SetEndpointID(42)

		// Second call - should now set up host EP
		m.UpdateBandwidthLimit(101, 2000000, 0)
		assert.True(t, m.hostEpDone.Load(), "hostEpDone should be true after host EP becomes available")

		// Verify host endpoint was inserted
		txn := db.ReadTxn()
		hostEntry, _, found := edtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 42,
			Direction:  DirectionEgress,
		}))
		require.True(t, found, "Host endpoint should be inserted")
		assert.Equal(t, uint32(GuaranteedQoSDefaultPriority), hostEntry.Prio)
	})
}

// setupTestDB creates a test StateDB with the EdtTable registered.
func setupTestDB(t *testing.T) (*statedb.DB, statedb.RWTable[bwmap.Edt]) {
	db := statedb.New()

	edtTable, err := bwmap.NewEdtTable(db)
	require.NoError(t, err, "Failed to create EdtTable")

	return db, edtTable
}

// newTestManager creates a manager with the minimum required parameters for testing.
func newTestManager(t *testing.T, db *statedb.DB, edtTable statedb.RWTable[bwmap.Edt]) *manager {
	return &manager{
		enabled: true,
		params: bandwidthManagerParams{
			Log:      hivetest.Logger(t),
			DB:       db,
			EdtTable: edtTable,
		},
	}
}
