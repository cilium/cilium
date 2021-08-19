// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2020 Authors of Cilium

//go:build !privileged_tests && !race
// +build !privileged_tests,!race

package idpool

import (
	. "gopkg.in/check.v1"
)

func (s *IDPoolTestSuite) TestAllocateID(c *C) {
	s.testAllocatedID(c, 256)
}
