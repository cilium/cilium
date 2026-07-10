// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestLocalLock(t *testing.T) {
	prefix := "locktest/"
	path := prefix + "foo"

	backup := staleLockTimeout
	defer func() { staleLockTimeout = backup }()
	staleLockTimeout = 5 * time.Millisecond

	locks := pathLocks{lockPaths: map[string]lockOwner{}}

	// Acquie lock1
	id1, err := locks.lock(context.Background(), path)
	require.NoError(t, err)

	// Ensure that staleLockTimeout has passed
	time.Sleep(staleLockTimeout * 2)
	locks.runGC(hivetest.Logger(t))

	// Acquire lock on same path, must unlock local use
	id2, err := locks.lock(context.Background(), path)
	require.NoError(t, err)

	// Unlock lock1, this should be a no-op
	locks.unlock(path, id1)

	owner, ok := locks.lockPaths[path]
	require.True(t, ok)
	require.Equal(t, id2, owner.id)

	// Unlock lock2, this should be a no-op
	locks.unlock(path, id2)
}

func TestLocalLockCancel(t *testing.T) {
	path := "locktest/foo"
	locks := pathLocks{lockPaths: map[string]lockOwner{}}
	// grab lock to ensure that 2nd lock attempt needs to retry and can be
	// cancelled
	id1, err := locks.lock(context.Background(), path)
	require.NoError(t, err)
	defer locks.unlock(path, id1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = locks.lock(ctx, path)
	require.Error(t, err)
}
