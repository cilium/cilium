// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rand

import (
	"strings"
	"testing"

	. "github.com/cilium/checkmate"
)

func Test(t *testing.T) {
	TestingT(t)
}

type RandSuite struct{}

var _ = Suite(&RandSuite{})

func (s *RandSuite) TestRandomString(c *C) {
	c.Assert(len(RandomString()), Equals, 12)

	c.Assert(len(RandomStringWithLen(12)), Equals, 12)
	c.Assert(len(RandomStringWithLen(0)), Equals, 0)

	s0 := RandomStringWithPrefix("foo", 12)
	c.Assert(len(s0), Equals, len("foo")+12)
	c.Assert(strings.HasPrefix(s0, "foo"), Equals, true)

	s1 := RandomLowercaseStringWithLen(15)
	c.Assert(len(s1), Equals, 15)
	c.Assert(strings.ToLower(s1), Equals, s1)
}
