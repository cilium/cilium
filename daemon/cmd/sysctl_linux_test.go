// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

//go:build linux && privileged_tests
// +build linux,privileged_tests

package cmd

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type DaemonPrivilegedSuite struct{}

var _ = Suite(&DaemonPrivilegedSuite{})

func (s *DaemonPrivilegedSuite) TestEnableIPForwarding(c *C) {
	err := enableIPForwarding()
	c.Assert(err, IsNil)
}
