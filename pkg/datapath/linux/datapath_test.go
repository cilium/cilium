// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

// +build !privileged_tests

package linux

import (
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type linuxTestSuite struct{}

var _ = check.Suite(&linuxTestSuite{})

func (s *linuxTestSuite) TestNewDatapath(c *check.C) {
	dp := NewDatapath(DatapathConfiguration{}, nil, nil)
	c.Assert(dp, check.Not(check.IsNil))

	c.Assert(dp.Node(), check.Not(check.IsNil))
	c.Assert(dp.LocalNodeAddressing(), check.Not(check.IsNil))
}
