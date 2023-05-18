// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"time"

	. "github.com/cilium/checkmate"
)

func (s *independentSuite) TestLocalLock(c *C) {
	prefix := "locktest/"
	path := prefix + "foo"

	backup := staleLockTimeout
	defer func() { staleLockTimeout = backup }()
	staleLockTimeout = 5 * time.Millisecond

	locks := pathLocks{lockPaths: map[string]lockOwner{}}

	// Acquie lock1
	id1, err := locks.lock(context.Background(), path)
	c.Assert(err, IsNil)

	// Ensure that staleLockTimeout has passed
	time.Sleep(staleLockTimeout * 2)
	locks.runGC()

	// Acquire lock on same path, must unlock local use
	id2, err := locks.lock(context.Background(), path)
	c.Assert(err, IsNil)

	// Unlock lock1, this should be a no-op
	locks.unlock(path, id1)

	owner, ok := locks.lockPaths[path]
	c.Assert(ok, Equals, true)
	c.Assert(owner.id, Equals, id2)

	// Unlock lock2, this should be a no-op
	locks.unlock(path, id2)
}

func (s *independentSuite) TestLocalLockCancel(c *C) {
	path := "locktest/foo"
	locks := pathLocks{lockPaths: map[string]lockOwner{}}
	// grab lock to ensure that 2nd lock attempt needs to retry and can be
	// cancelled
	id1, err := locks.lock(context.Background(), path)
	c.Assert(err, IsNil)
	defer locks.unlock(path, id1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = locks.lock(ctx, path)
	c.Assert(err, Not(IsNil))
}
