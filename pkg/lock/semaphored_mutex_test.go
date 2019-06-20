// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package lock

import (
	. "gopkg.in/check.v1"
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
