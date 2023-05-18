// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	. "github.com/cilium/checkmate"
)

type SemaphoredMutexSuite struct{}

var _ = Suite(&SemaphoredMutexSuite{})

func (s *SemaphoredMutexSuite) TestLock(c *C) {
	lock1 := NewSemaphoredMutex()
	lock1.Lock()
	lock1.Unlock()

	lock1.RLock()
	lock1.RUnlock()

	lock2 := NewSemaphoredMutex()
	lock2.Lock()
	lock2.Unlock()

	lock2.Lock()
	lock2.UnlockToRLock()

	lock2.RLock()
	lock2.RLock()

	lock2.RUnlock()
	lock2.RUnlock()
	lock2.RUnlock()

}
