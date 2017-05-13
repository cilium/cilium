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

	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	CONSUMER_ID1 = NumericIdentity(10)
	CONSUMER_ID2 = NumericIdentity(20)
	CONSUMER_ID3 = NumericIdentity(30)
)

func (s *PolicyTestSuite) TestNewConsumer(c *C) {
	consumer := NewConsumer(CONSUMER_ID1)
	c.Assert(consumer.ID, Equals, CONSUMER_ID1)
	c.Assert(consumer.Decision, Equals, api.Allowed)
}

func (s *PolicyTestSuite) TestGetConsumer(c *C) {
	cache := NewConsumableCache()

	c1 := cache.GetOrCreate(CONSUMER_ID1, nil)
	c.Assert(c1.Iteration, Equals, 0)
	c2 := cache.GetOrCreate(CONSUMER_ID1, nil)
	c.Assert(c1, Equals, c2)

	c3 := cache.GetOrCreate(CONSUMER_ID2, nil)
	c.Assert(c1, Not(Equals), c3)
}

func (s *PolicyTestSuite) TestConsumer(c *C) {
	cache := NewConsumableCache()

	c1 := cache.GetOrCreate(CONSUMER_ID1, nil)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, false)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, false)

	c1.AllowConsumerLocked(cache, CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, true)
	consumer1 := c1.getConsumer(CONSUMER_ID2)
	c.Assert(consumer1.ID, Equals, CONSUMER_ID2)

	c1.AllowConsumerLocked(cache, CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, true)
	consumer2 := c1.getConsumer(CONSUMER_ID2)
	c.Assert(consumer2.ID, Equals, CONSUMER_ID2)

	c1.AllowConsumerLocked(cache, CONSUMER_ID3)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, true)
	consumer3 := c1.getConsumer(CONSUMER_ID3)
	c.Assert(consumer3.ID, Equals, CONSUMER_ID3)

	c1.BanConsumerLocked(CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, false)
	consumer2 = c1.getConsumer(CONSUMER_ID2)
	c.Assert(consumer2, IsNil)

	c1.BanConsumerLocked(CONSUMER_ID3)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, false)
	consumer3 = c1.getConsumer(CONSUMER_ID3)
	c.Assert(consumer3, IsNil)
}
