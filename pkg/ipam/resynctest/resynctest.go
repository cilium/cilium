// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package resynctest checks that an IPAM cache update made during a full
// cloud API resync survives it.
package resynctest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
)

type resyncer interface {
	Resync(ctx context.Context) (time.Time, error)
}

// RunDuringFullResync runs cloudSetup and then cacheUpdate inside the cloud fetch window of a full resync.
// setHook installs the function the fake cloud API calls when the full resync's fetch returns.
func RunDuringFullResync(t *testing.T, mngr resyncer, setHook func(func()), cloudSetup func() error, cacheUpdate func()) {
	t.Helper()

	// An unguarded cacheUpdate must land within this much of the fetch window for the resync to drop it.
	const detectionBudget = 2 * time.Second
	// Only a locking regression keeps cloudSetup or cacheUpdate waiting this long.
	const progressTimeout = 10 * time.Second

	var setupErr error
	var setupStalled bool
	atCacheUpdate := make(chan struct{})
	done := make(chan struct{})
	hookReturned := make(chan struct{})

	// The resync goroutine runs this hook, so it records what it saw and never calls t itself.
	setHook(func() {
		defer close(hookReturned)
		go func() {
			defer close(done)
			if setupErr = cloudSetup(); setupErr != nil {
				return
			}
			close(atCacheUpdate)
			cacheUpdate()
		}()

		// Keep the cloud calls out of the budget below, and never wait on a setup that gave up.
		select {
		case <-atCacheUpdate:
		case <-done:
			return
		case <-time.After(progressTimeout):
			setupStalled = true
			return
		}

		// A guarded cacheUpdate waits for resyncLock, so this select always spends the whole budget.
		select {
		case <-done:
		case <-time.After(detectionBudget):
		}
	})

	ctx := t.Context()
	resynced := make(chan error, 1)
	go func() {
		_, err := mngr.Resync(ctx)
		resynced <- err
	}()

	// The hook owns progressTimeout plus the budget, so wait that out before blaming the resync.
	select {
	case <-hookReturned:
	case <-time.After(progressTimeout + detectionBudget + time.Second):
		t.Fatalf("the full resync did not reach its cloud fetch hook within %v", progressTimeout)
	}
	require.False(t, setupStalled, "cloud setup neither reached the cache update nor failed within %v", progressTimeout)

	// A cacheUpdate that takes the locks in the wrong order deadlocks the publish after the hook.
	select {
	case err := <-resynced:
		require.NoError(t, err)
	case <-time.After(progressTimeout):
		t.Fatalf("the full resync did not publish within %v of its fetch window; cacheUpdate holds a lock it needs", progressTimeout)
	}

	select {
	case <-done:
	case <-time.After(progressTimeout):
		t.Fatalf("cache update still blocked %v after the full resync released resyncLock", progressTimeout)
	}

	setHook(nil)
	require.NoError(t, setupErr)
}

type eniCache[E any] interface {
	resyncer
	ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator)
	UpdateENI(instanceID string, eni E)
}

// ENIUpdate checks that an ENI attached inside the cloud fetch window of a full resync survives it.
func ENIUpdate[E any](t *testing.T, mngr eniCache[E], setHook func(func()), instanceID string, attach func() (string, E, error)) {
	t.Helper()

	before := cachedENIIDs(mngr, instanceID)
	require.NotEmpty(t, before)

	var eniID string
	var eni E
	RunDuringFullResync(t, mngr, setHook,
		func() (err error) {
			eniID, eni, err = attach()
			return err
		},
		func() {
			mngr.UpdateENI(instanceID, eni)
		})

	require.ElementsMatch(t, append(before, eniID), cachedENIIDs(mngr, instanceID))
}

func cachedENIIDs[E any](mngr eniCache[E], instanceID string) (ids []string) {
	mngr.ForeachInstance(instanceID, func(_, ifaceID string, _ ipamTypes.Interface) error {
		ids = append(ids, ifaceID)
		return nil
	})
	return ids
}
