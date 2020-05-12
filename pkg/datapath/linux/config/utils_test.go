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

package config

import (
	"testing"

	. "gopkg.in/check.v1"
)

type ConfigSuite struct{}

var (
	_ = Suite(&ConfigSuite{})
)

func Test(t *testing.T) {
	TestingT(t)
}

type formatTestCase struct {
	input  []byte
	output string
}

func (s *ConfigSuite) TestdefineIPv6(c *C) {
	tests := []formatTestCase{
		{
			input:  nil,
			output: "/* BUG: bad ip define foo  */\n",
		},
		{
			input:  []byte{},
			output: "/* BUG: bad ip define foo  */\n",
		},
		{
			input:  []byte{1, 2, 3},
			output: "/* BUG: bad ip define foo 0x1, 0x2, 0x3 */\n",
		},
		{
			input: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			output: "DEFINE_IPV6(foo, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10);\n" +
				"#define foo_V\n",
		},
	}

	for _, test := range tests {
		c.Assert(defineIPv6("foo", test.input), Equals, test.output)
	}
}

func (s *ConfigSuite) TestdefineMAC(c *C) {
	tests := []formatTestCase{
		{
			input:  nil,
			output: "/* BUG: bad mac define foo  */\n",
		},
		{
			input:  []byte{},
			output: "/* BUG: bad mac define foo  */\n",
		},
		{
			input:  []byte{1, 2, 3},
			output: "/* BUG: bad mac define foo 0x1, 0x2, 0x3 */\n",
		},
		{
			input: []byte{1, 2, 3, 4, 5, 6},
			output: "DEFINE_MAC(foo, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6);\n" +
				"#define foo fetch_mac(foo)\n",
		},
	}
	for _, test := range tests {
		c.Assert(defineMAC("foo", test.input), Equals, test.output)
	}
}
