// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestIdentityHeartbeatStore(t *testing.T) {
	store := newHeartbeatStore(time.Second, hivetest.Logger(t))

	// mark lifesign to now, identity must be alive, run GC, identity
	// should still exist
	store.markAlive("foo", time.Now())
	require.True(t, store.isAlive("foo"))
	store.gc()
	require.True(t, store.isAlive("foo"))

	// mark lifesign in the past, identity should not be alive anymore
	store.markAlive("foo", time.Now().Add(-time.Minute))
	require.False(t, store.isAlive("foo"))

	// mark lifesign way in the past, run GC, validate that identity is no
	// longer tracked
	store.markAlive("foo", time.Now().Add(-24*time.Hour))
	require.False(t, store.isAlive("foo"))
	store.gc()
	store.mutex.RLock()
	_, ok := store.lastLifesign["foo"]
	require.False(t, ok)
	store.mutex.RUnlock()

	// mark lifesign to now and validate deletion
	store.markAlive("foo", time.Now())
	store.mutex.RLock()
	_, ok = store.lastLifesign["foo"]
	store.mutex.RUnlock()
	require.True(t, ok)
	store.delete("foo")
	store.mutex.RLock()
	_, ok = store.lastLifesign["foo"]
	store.mutex.RUnlock()
	require.False(t, ok)

	// identity foo now doesn't exist, simulate start time of operator way
	// in the past to check if an old, stale identity will be deleted
	store.firstRun = time.Now().Add(-24 * time.Hour)
	require.False(t, store.isAlive("foo"))
}
