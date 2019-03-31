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
	key, keyObj, val := "foo", TestType("foo"), idpool.ID(200)
	key2, key2Obj, val2 := "bar", TestType("bar"), idpool.ID(300)

	v := k.use(key)
	c.Assert(v, Equals, idpool.NoID)

	v, err := k.allocate(key, keyObj, val) // refcnt=1
	c.Assert(err, IsNil)
	c.Assert(v, Equals, val)

	c.Assert(k.verify(key), IsNil)

	v = k.use(key) // refcnt=2
	c.Assert(v, Equals, val)
	k.release(key) // refcnt=1

	v, err = k.allocate(key, keyObj, val) // refcnt=2
	c.Assert(err, IsNil)
	c.Assert(v, Equals, val)

	v, err = k.allocate(key2, key2Obj, val2) // refcnt=1
	c.Assert(err, IsNil)
	c.Assert(v, Equals, val2)

	// only one of the two keys is verified yet
	ids := k.getVerifiedIDs()
	c.Assert(len(ids), Equals, 1)

	// allocate with different value must fail
	_, err = k.allocate(key2, key2Obj, val)
	c.Assert(err, Not(IsNil))

	k.release(key) // refcnt=1
	v = k.use(key) // refcnt=2
	c.Assert(v, Equals, val)

	k.release(key) // refcnt=1
	k.release(key) // refcnt=0
	v = k.use(key)
	c.Assert(v, Equals, idpool.NoID)

	k.release(key2) // refcnt=0
	v = k.use(key2)
	c.Assert(v, Equals, idpool.NoID)
}
