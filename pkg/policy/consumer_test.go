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

package policy

import (
	. "gopkg.in/check.v1"
)

const (
	ID1 = NumericIdentity(10)
	ID2 = NumericIdentity(20)
	ID3 = NumericIdentity(30)
)

func (s *PolicyTestSuite) TestGetConsumable(c *C) {
	cache := newConsumableCache()

	c1 := cache.GetOrCreate(ID1, nil)
	c.Assert(c1.Iteration, Equals, uint64(0))
	c2 := cache.GetOrCreate(ID1, nil)
	c.Assert(c1, Equals, c2)

	c3 := cache.GetOrCreate(ID2, nil)
	c.Assert(c1, Not(Equals), c3)
}

func (s *PolicyTestSuite) TestIdentityAllowed(c *C) {
	cache := newConsumableCache()

	c1 := cache.GetOrCreate(ID1, nil)
	c.Assert(c1.Allows(ID2), Equals, false)
	c.Assert(c1.Allows(ID3), Equals, false)

	c1.AllowIngressIdentityLocked(cache, ID2)
	c.Assert(c1.Allows(ID2), Equals, true)
	id2Allowed, _ := c1.IngressIdentities[ID2]
	c.Assert(id2Allowed, Equals, true)

	c1.AllowIngressIdentityLocked(cache, ID2)
	c.Assert(c1.Allows(ID2), Equals, true)
	id2Allowed, _ = c1.IngressIdentities[ID2]
	c.Assert(id2Allowed, Equals, true)

	c1.AllowIngressIdentityLocked(cache, ID3)
	c.Assert(c1.Allows(ID3), Equals, true)
	id3Allowed, _ := c1.IngressIdentities[ID3]
	c.Assert(id3Allowed, Equals, true)

	c1.RemoveIngressIdentityLocked(ID2)
	c.Assert(c1.Allows(ID2), Equals, false)
	id2Allowed, _ = c1.IngressIdentities[ID2]
	c.Assert(id2Allowed, Equals, false)

	c1.RemoveIngressIdentityLocked(ID3)
	c.Assert(c1.Allows(ID3), Equals, false)
	id3Allowed, _ = c1.IngressIdentities[ID3]
	c.Assert(id3Allowed, Equals, false)
}
