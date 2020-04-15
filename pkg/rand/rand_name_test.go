// Copyright 2018 Authors of Cilium
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

package rand

import (
	"strings"
	"testing"

	. "gopkg.in/check.v1"
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
