// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"time"

	. "github.com/cilium/checkmate"
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
