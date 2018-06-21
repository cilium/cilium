// Copyright 2018 Authors of Cilium
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

package ipcache

import (
	"fmt"

	"github.com/cilium/cilium/pkg/identity"

	. "gopkg.in/check.v1"
)

type testStore map[string]int

func (ts testStore) upsert(key string, value []byte, lease bool) error {
	refcnt, ok := ts[key]
	if ok {
		ts[key] = refcnt + 1
	} else {
		ts[key] = 1
	}
	return nil
}

func (ts testStore) release(key string) error {
	_, ok := ts[key]
	if !ok {
		return fmt.Errorf("Unexpected delete from underlying store")
	}
	delete(ts, key)
	return nil
}

func (s *IPCacheTestSuite) TestKVReferenceCounter(c *C) {
	ts := testStore{}
	refcnt := newKVReferenceCounter(ts)

	// Add two references to "foo"; we should see two updates.
	key1 := "foo"
	err := refcnt.upsert(key1, identity.IPIdentityPair{})
	c.Assert(err, IsNil)
	c.Assert(ts[key1], Equals, 1)
	err = refcnt.upsert(key1, identity.IPIdentityPair{})
	c.Assert(err, IsNil)
	c.Assert(ts[key1], Equals, 2)

	// Remove one reference, "foo" should still map to 2
	err = refcnt.release(key1)
	c.Assert(err, IsNil)
	c.Assert(ts[key1], Equals, 2)
	// Remove the second referenc, "foo" should be deleted from the store.
	err = refcnt.release(key1)
	c.Assert(err, IsNil)
	_, ok := ts[key1]
	c.Assert(ok, Equals, false)

	// Create two keys at once
	key2 := "bar"
	err = refcnt.upsert(key1, identity.IPIdentityPair{})
	c.Assert(err, IsNil)
	c.Assert(ts[key1], Equals, 1)
	err = refcnt.upsert(key2, identity.IPIdentityPair{})
	c.Assert(err, IsNil)
	c.Assert(ts[key2], Equals, 1)

	// Remove one of the keys. The other remains.
	err = refcnt.release(key1)
	c.Assert(err, IsNil)
	_, ok = ts[key1]
	c.Assert(ok, Equals, false)
	_, ok = ts[key2]
	c.Assert(ok, Equals, true)
}
