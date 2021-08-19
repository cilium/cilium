// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2020 Authors of Cilium

//go:build !privileged_tests && race
// +build !privileged_tests,race

package idpool

import (
	. "gopkg.in/check.v1"
)

// TestAllocateID without the race detection enabled is too slow to run with
// race detector set. Thus, we need to put it in a separate file so the unit
// tests don't time out while running with race detector by having a lower
// number of parallel go routines than it would have been if we ran it without
// the race detector.
func (s *IDPoolTestSuite) TestAllocateID(c *C) {
	s.testAllocatedID(c, 5)
}
