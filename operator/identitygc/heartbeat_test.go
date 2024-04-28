// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIdentityHeartbeatStore(t *testing.T) {
	store := newHeartbeatStore(time.Second)

	// mark lifesign to now, identity must be alive, run GC, identity
	// should still exist
	store.markAlive("foo", time.Now())
	require.Equal(t, true, store.isAlive("foo"))
	store.gc()
	require.Equal(t, true, store.isAlive("foo"))

	// mark lifesign in the past, identity should not be alive anymore
	store.markAlive("foo", time.Now().Add(-time.Minute))
	require.Equal(t, false, store.isAlive("foo"))

	// mark lifesign way in the past, run GC, validate that identity is no
	// longer tracked
	store.markAlive("foo", time.Now().Add(-24*time.Hour))
	require.Equal(t, false, store.isAlive("foo"))
	store.gc()
	store.mutex.RLock()
	_, ok := store.lastLifesign["foo"]
	require.Equal(t, false, ok)
	store.mutex.RUnlock()

	// mark lifesign to now and validate deletion
	store.markAlive("foo", time.Now())
	store.mutex.RLock()
	_, ok = store.lastLifesign["foo"]
	store.mutex.RUnlock()
	require.Equal(t, true, ok)
	store.delete("foo")
	store.mutex.RLock()
	_, ok = store.lastLifesign["foo"]
	store.mutex.RUnlock()
	require.Equal(t, false, ok)

	// identity foo now doesn't exist, simulate start time of operator way
	// in the past to check if an old, stale identity will be deleted
	store.firstRun = time.Now().Add(-24 * time.Hour)
	require.Equal(t, false, store.isAlive("foo"))
}
