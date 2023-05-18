// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"time"

	. "github.com/cilium/checkmate"
)

func (s *TestUtilsSuite) TestCondition(c *C) {
	c.Assert(WaitUntil(func() bool { return false }, 50*time.Millisecond), Not(IsNil))
	c.Assert(WaitUntil(func() bool { return true }, 50*time.Millisecond), IsNil)

	counter := 0
	countTo5 := func() bool {
		if counter > 5 {
			return true
		}
		counter++
		return false
	}

	c.Assert(WaitUntil(countTo5, 1*time.Millisecond), Not(IsNil))

	counter = 0
	c.Assert(WaitUntil(countTo5, time.Second), IsNil)
}
