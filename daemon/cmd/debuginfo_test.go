// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build integration_tests

package cmd

import (
	"os"

	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestMemoryMap(c *C) {
	pid := os.Getpid()
	m := memoryMap(pid)
	c.Assert(m, Not(Equals), "")
}
