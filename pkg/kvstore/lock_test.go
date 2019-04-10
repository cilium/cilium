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

package kvstore

import (
	"context"
	"time"

	"github.com/pborman/uuid"
	. "gopkg.in/check.v1"
)

func (s *independentSuite) TestLocalLock(c *C) {
	prefix := "locktest/"
	path := prefix + "foo"

	backup := staleLockTimeout
	defer func() { staleLockTimeout = backup }()
	staleLockTimeout = 5 * time.Millisecond

	locks := pathLocks{lockPaths: map[string]uuid.UUID{}}

	// Acquie lock1
	id1 := locks.lock(context.Background(), path)

	// Ensure that staleLockTimeout has passed
	time.Sleep(staleLockTimeout)

	// Acquire lock on same path, must unlock local use
	id2 := locks.lock(context.Background(), path)

	// Unlock lock1, this should be a no-op
	locks.unlock(path, id1)

	l, ok := locks.lockPaths[path]
	c.Assert(ok, Equals, true)
	c.Assert(uuid.Equal(l, id2), Equals, true)

	// Unlock lock2, this should be a no-op
	locks.unlock(path, id2)
}
