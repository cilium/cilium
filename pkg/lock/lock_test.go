// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LockSuite struct{}

var _ = Suite(&LockSuite{})

func (s *LockSuite) TestLock(c *C) {
	var lock1 RWMutex
	lock1.Lock()
	lock1.Unlock()

	lock1.RLock()
	lock1.RUnlock()

	var lock2 Mutex
	lock2.Lock()
	lock2.Unlock()
}

func (s *LockSuite) TestDebugLock(c *C) {
	var lock1 RWMutexDebug
	lock1.Lock()
	lock1.Unlock()

	lock1.RLock()
	lock1.RUnlock()

	var lock2 MutexDebug
	lock2.Lock()
	lock2.Unlock()
}
