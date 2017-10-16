// Copyright 2016-2017 Authors of Cilium
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

package common

import (
	"testing"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type CommonSuite struct{}

var _ = check.Suite(&CommonSuite{})

func (s *CommonSuite) TestGoArray2C(c *check.C) {
	c.Assert(goArray2C([]byte{0, 0x01, 0x02, 0x03}), check.Equals, "0x0, 0x1, 0x2, 0x3")
	c.Assert(goArray2C([]byte{0, 0xFF, 0xFF, 0xFF}), check.Equals, "0x0, 0xff, 0xff, 0xff")
	c.Assert(goArray2C([]byte{0xa, 0xbc, 0xde, 0xf1}), check.Equals, "0xa, 0xbc, 0xde, 0xf1")
	c.Assert(goArray2C([]byte{0}), check.Equals, "0x0")
	c.Assert(goArray2C([]byte{}), check.Equals, "")
}

func (s *CommonSuite) TestFmtDefineComma(c *check.C) {
	c.Assert(FmtDefineComma("foo", []byte{1, 2, 3}), check.Equals, "#define foo 0x1, 0x2, 0x3\n")
	c.Assert(FmtDefineComma("foo", []byte{}), check.Equals, "#define foo \n")
}

func (s *CommonSuite) TestFmtDefineAddress(c *check.C) {
	c.Assert(FmtDefineAddress("foo", []byte{1, 2, 3}), check.Equals, "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n")
	c.Assert(FmtDefineAddress("foo", []byte{}), check.Equals, "#define foo { .addr = {  } }\n")
}

func (s *CommonSuite) TestFmtDefineArray(c *check.C) {
	c.Assert(FmtDefineArray("foo", []byte{1, 2, 3}), check.Equals, "#define foo { 0x1, 0x2, 0x3 }\n")
	c.Assert(FmtDefineArray("foo", []byte{}), check.Equals, "#define foo {  }\n")
}
