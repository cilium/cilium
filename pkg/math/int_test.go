// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package math

import (
	"testing"

	check "github.com/cilium/checkmate"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MathSuite struct{}

var _ = check.Suite(&MathSuite{})

const (
	maxIntValue = int(^uint(0) >> 1)
	minIntValue = -maxIntValue - 1
)

func (b *MathSuite) TestIntMin(c *check.C) {
	c.Assert(IntMin(10, 20), check.Equals, 10)
	c.Assert(IntMin(20, 10), check.Equals, 10)
	c.Assert(IntMin(10, 10), check.Equals, 10)
	c.Assert(IntMin(-10, 10), check.Equals, -10)
	c.Assert(IntMin(0, 10), check.Equals, 0)
	c.Assert(IntMin(minIntValue, maxIntValue), check.Equals, minIntValue)
}

func (b *MathSuite) TestIntMax(c *check.C) {
	c.Assert(IntMax(10, 20), check.Equals, 20)
	c.Assert(IntMax(20, 10), check.Equals, 20)
	c.Assert(IntMax(10, 10), check.Equals, 10)
	c.Assert(IntMax(-10, 10), check.Equals, 10)
	c.Assert(IntMax(0, 10), check.Equals, 10)
	c.Assert(IntMax(minIntValue, maxIntValue), check.Equals, maxIntValue)
}
