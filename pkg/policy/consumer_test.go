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
	CONSUMER_ID1 = NumericIdentity(10)
	CONSUMER_ID2 = NumericIdentity(20)
	CONSUMER_ID3 = NumericIdentity(30)
)

func (s *PolicyTestSuite) TestGetConsumer(c *C) {
	cache := newConsumableCache()

	c1 := cache.GetOrCreate(CONSUMER_ID1, nil)
	c.Assert(c1.Iteration, Equals, uint64(0))
	c2 := cache.GetOrCreate(CONSUMER_ID1, nil)
	c.Assert(c1, Equals, c2)

	c3 := cache.GetOrCreate(CONSUMER_ID2, nil)
	c.Assert(c1, Not(Equals), c3)
}


// TODO (ianvernon) this might not be needed.
func (s *PolicyTestSuite) TestConsumer(c *C) {
	cache := newConsumableCache()

	c1 := cache.GetOrCreate(CONSUMER_ID1, nil)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, false)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, false)

	c1.AllowIngressConsumerLocked(cache, CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, true)

	c1.AllowIngressConsumerLocked(cache, CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, true)

	c1.AllowIngressConsumerLocked(cache, CONSUMER_ID3)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, true)

	c1.BanIngressConsumerLocked(CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, false)

	c1.BanIngressConsumerLocked(CONSUMER_ID3)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, false)
}
