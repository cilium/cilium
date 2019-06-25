// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package math

import (
	"testing"

	"gopkg.in/check.v1"
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
