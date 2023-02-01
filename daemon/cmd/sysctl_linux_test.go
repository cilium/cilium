// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

type DaemonPrivilegedSuite struct{}

var _ = Suite(&DaemonPrivilegedSuite{})

func (s *DaemonPrivilegedSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)
}

func (s *DaemonPrivilegedSuite) TestEnableIPForwarding(c *C) {
	err := enableIPForwarding()
	c.Assert(err, IsNil)
}
