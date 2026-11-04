// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package resynctest checks that an IPAM cache update made during a full or
// partial cloud API resync survives it.
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

// RunDuringResync runs cloudSetup and then cacheUpdate while a full or partial
// resync holds its cloud snapshot before publishing it. setHook installs the
// function the fake cloud API calls after capturing the snapshot and before
// returning it to the resync.
func RunDuringResync(t *testing.T, mngr resyncer, setHook func(func()), cloudSetup func() error, cacheUpdate func()) {
	t.Helper()

	// Give an unguarded cacheUpdate time to finish before the delayed snapshot
	// returns, allowing the resync to expose a stale overwrite.
	const detectionBudget = 2 * time.Second
	// Bound waits for cloud setup, snapshot publication, and the cache update.
	const progressTimeout = 10 * time.Second

	var setupErr error
	var setupStalled bool
	atCacheUpdate := make(chan struct{})
	done := make(chan struct{})
	hookReturned := make(chan struct{})

	// The resync goroutine runs this hook. Record progress here and report
	// failures from the test goroutine.
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

		// Wait for cloudSetup before starting the cache-update detection window.
		select {
		case <-atCacheUpdate:
		case <-done:
			return
		case <-time.After(progressTimeout):
			setupStalled = true
			return
		}

		// A serialized cacheUpdate waits for the resync to finish. Let the
		// snapshot return when the detection budget expires so it can proceed.
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

	// Allow time for cloudSetup and the detection window before checking
	// whether the resync returned from its snapshot hook.
	select {
	case <-hookReturned:
	case <-time.After(progressTimeout + detectionBudget + time.Second):
		t.Fatalf("resync did not return from its cloud snapshot hook within %v", progressTimeout+detectionBudget+time.Second)
	}
	require.False(t, setupStalled, "cloud setup neither reached the cache update nor failed within %v", progressTimeout)

	// Wait for snapshot publication. A cacheUpdate that takes locks in the
	// wrong order can block the resync after its snapshot hook returns.
	select {
	case err := <-resynced:
		require.NoError(t, err)
	case <-time.After(progressTimeout):
		t.Fatalf("resync did not publish within %v after its snapshot hook returned; cacheUpdate may hold a lock it needs", progressTimeout)
	}

	// Once the resync completes, a serialized cacheUpdate must also finish.
	select {
	case <-done:
	case <-time.After(progressTimeout):
		t.Fatalf("cache update still blocked %v after the resync completed", progressTimeout)
	}

	setHook(nil)
	require.NoError(t, setupErr)
}

type eniCache[E any] interface {
	resyncer
	ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator)
	UpdateENI(instanceID string, eni E)
}

// ENIUpdate checks that an ENI attached while a resync holds its cloud snapshot survives it.
func ENIUpdate[E any](t *testing.T, mngr eniCache[E], setHook func(func()), instanceID string, attach func() (string, E, error)) {
	t.Helper()

	before := cachedENIIDs(mngr, instanceID)
	require.NotEmpty(t, before)

	var eniID string
	var eni E
	RunDuringResync(t, mngr, setHook,
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

type instancesManager interface {
	resyncer
	HasInstance(instanceID string) bool
	DeleteInstance(instanceID string)
}

// InstanceDelete checks that an instance deleted while a resync holds its cloud snapshot stays deleted.
func InstanceDelete(t *testing.T, mngr instancesManager, setHook func(func()), instanceID string) {
	t.Helper()

	require.True(t, mngr.HasInstance(instanceID))
	RunDuringResync(t, mngr, setHook,
		func() error { return nil },
		func() {
			mngr.DeleteInstance(instanceID)
		})
	require.False(t, mngr.HasInstance(instanceID))
}
