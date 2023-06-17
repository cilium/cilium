// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"testing"
	"time"

	check "github.com/cilium/checkmate"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type OperatorTestSuite struct{}

var _ = check.Suite(&OperatorTestSuite{})

func (s *OperatorTestSuite) TestIdentityHeartbeatStore(c *check.C) {
	store := newHeartbeatStore(time.Second)

	// mark lifesign to now, identity must be alive, run GC, identity
	// should still exist
	store.markAlive("foo", time.Now())
	c.Assert(store.isAlive("foo"), check.Equals, true)
	store.gc()
	c.Assert(store.isAlive("foo"), check.Equals, true)

	// mark lifesign in the past, identity should not be alive anymore
	store.markAlive("foo", time.Now().Add(-time.Minute))
	c.Assert(store.isAlive("foo"), check.Equals, false)

	// mark lifesign way in the past, run GC, validate that identity is no
	// longer tracked
	store.markAlive("foo", time.Now().Add(-24*time.Hour))
	c.Assert(store.isAlive("foo"), check.Equals, false)
	store.gc()
	store.mutex.RLock()
	_, ok := store.lastLifesign["foo"]
	c.Assert(ok, check.Equals, false)
	store.mutex.RUnlock()

	// mark lifesign to now and validate deletion
	store.markAlive("foo", time.Now())
	store.mutex.RLock()
	_, ok = store.lastLifesign["foo"]
	store.mutex.RUnlock()
	c.Assert(ok, check.Equals, true)
	store.delete("foo")
	store.mutex.RLock()
	_, ok = store.lastLifesign["foo"]
	store.mutex.RUnlock()
	c.Assert(ok, check.Equals, false)

	// identtity foo now doesn't exist, simulate start time of operator way
	// in the past to check if an old, stale identity will be deleeted
	store.firstRun = time.Now().Add(-24 * time.Hour)
	c.Assert(store.isAlive("foo"), check.Equals, false)
}
