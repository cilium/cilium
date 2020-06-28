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

// +build !privileged_tests

package allocator

import (
	"github.com/cilium/cilium/pkg/idpool"

	. "gopkg.in/check.v1"
)

func (s *AllocatorSuite) TestLocalKeys(c *C) {
	k := newLocalKeys()
	key, val := TestAllocatorKey("foo"), idpool.ID(200)
	key2, val2 := TestAllocatorKey("bar"), idpool.ID(300)

	v := k.use(key.GetKey())
	c.Assert(v, Equals, idpool.NoID)

	v, firstUse, err := k.allocate(key.GetKey(), key, val) // refcnt=1
	c.Assert(err, IsNil)
	c.Assert(v, Equals, val)
	c.Assert(firstUse, Equals, true)

	c.Assert(k.verify(key.GetKey()), IsNil)

	v = k.use(key.GetKey()) // refcnt=2
	c.Assert(v, Equals, val)
	k.release(key.GetKey()) // refcnt=1

	v, firstUse, err = k.allocate(key.GetKey(), key, val) // refcnt=2
	c.Assert(err, IsNil)
	c.Assert(v, Equals, val)
	c.Assert(firstUse, Equals, false)

	v, firstUse, err = k.allocate(key2.GetKey(), key2, val2) // refcnt=1
	c.Assert(err, IsNil)
	c.Assert(v, Equals, val2)
	c.Assert(firstUse, Equals, true)

	// only one of the two keys is verified yet
	ids := k.getVerifiedIDs()
	c.Assert(len(ids), Equals, 1)

	// allocate with different value must fail
	_, _, err = k.allocate(key2.GetKey(), key2, val)
	c.Assert(err, Not(IsNil))

	k.release(key.GetKey()) // refcnt=1
	v = k.use(key.GetKey()) // refcnt=2
	c.Assert(v, Equals, val)

	k.release(key.GetKey()) // refcnt=1
	k.release(key.GetKey()) // refcnt=0
	v = k.use(key.GetKey())
	c.Assert(v, Equals, idpool.NoID)

	k.release(key2.GetKey()) // refcnt=0
	v = k.use(key2.GetKey())
	c.Assert(v, Equals, idpool.NoID)
}
