// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package datapath

import (
	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
)

type DaemonPrivilegedSuite struct{}

var _ = Suite(&DaemonPrivilegedSuite{})

func (s *DaemonPrivilegedSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (s *DaemonPrivilegedSuite) TestEnableIPForwarding(c *C) {
	err := enableIPForwarding()
	c.Assert(err, IsNil)
}
