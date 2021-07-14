// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

// +build privileged_tests

package mtu

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MTUSuite struct{}

var _ = Suite(&MTUSuite{})

func (m *MTUSuite) TestAutoDetect(c *C) {
	mtu, err := autoDetect()
	c.Assert(err, IsNil)
	c.Assert(mtu, Not(Equals), 0)
}
