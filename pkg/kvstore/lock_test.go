// Copyright 2016-2017 Authors of Cilium
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

package kvstore

import (
	. "gopkg.in/check.v1"
)

func (s *KvstoreSuite) TestGetLockPath(c *C) {
	const path = "foo/path"
	c.Assert(getLockPath(path), Equals, path+".lock")
}

func (s *KvstoreSuite) TestLockPath(c *C) {
	const path = "foo/path"
	kvStore := &KVStoreMocker{
		OnLockPath: func(path string) (kvLocker, error) {
			return KVLockerMocker{
				OnUnlock: func() error {
					return nil
				},
			}, nil
		},
		OnKeepAlive: func(lease interface{}) error {
			return nil
		},
	}

	clientInstance = kvStore

	l, err := LockPath(path)
	c.Assert(err, IsNil)

	lockPathsMU.RLock()
	// Check the number of lockPaths is only 1
	c.Assert(len(lockPaths), Equals, 1)
	lockPathsMU.RUnlock()

	done := make(chan struct{})
	var l2 *Lock
	go func() {
		// inside routine
		l2, err = LockPath(path)
		c.Assert(err, IsNil)
		close(done)
	}()

	select {
	case <-done:
		c.Fatalf("Lock on %s should not have happen as local lock is still locked", path)
	default:
		l.Unlock()
	}

	// Still wait for the goroutine spawn to finish
	<-done

	lockPathsMU.RLock()
	// Check the number of lockPaths is still 1
	c.Assert(len(lockPaths), Equals, 1)
	lockPathsMU.RUnlock()

	l2.Unlock()

	lockPathsMU.RLock()
	// Check the number of lockPaths should be 0
	c.Assert(len(lockPaths), Equals, 0)
	lockPathsMU.RUnlock()
}
