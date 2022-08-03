// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !race

package idpool

import (
	. "gopkg.in/check.v1"
)

func (s *IDPoolTestSuite) TestAllocateID(c *C) {
	s.testAllocatedID(c, 256)
}
