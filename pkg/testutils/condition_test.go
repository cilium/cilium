// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package testutils

import (
	"time"

	. "gopkg.in/check.v1"
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
	c.Assert(WaitUntil(countTo5, 100*time.Millisecond), IsNil)
}
