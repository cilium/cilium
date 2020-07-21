// Copyright 2020 Authors of Cilium
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

package logging

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *LoggingSuite) TestLimiter(c *C) {
	// Set up a limiter that allows one event every half second with the burts of 3.
	// The underlying token bucket has the capacity of three and fill rate of
	// 2 per second.
	limiter := NewLimiter(500*time.Millisecond, 3)

	// Initially tree events should be allowed and the rest denied.
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, false)
	c.Assert(limiter.Allow(), Equals, false)
	c.Assert(limiter.Allow(), Equals, false)

	// After half second one more event should be allowed, the rest denied
	time.Sleep(500 * time.Millisecond)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, false)
	c.Assert(limiter.Allow(), Equals, false)

	// After one more second two events should be allowed, the rest denied
	time.Sleep(1 * time.Second)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, false)
	c.Assert(limiter.Allow(), Equals, false)

	// After two more seconds three events should be allowed, the rest denied
	time.Sleep(2 * time.Second)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, true)
	c.Assert(limiter.Allow(), Equals, false)
	c.Assert(limiter.Allow(), Equals, false)
}
