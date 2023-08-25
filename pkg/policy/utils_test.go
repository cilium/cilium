// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	. "github.com/cilium/checkmate"
)

func (s *PolicyTestSuite) TestJoinPath(c *C) {
	var joinPathTests = []struct {
		input1   string // input 1
		input2   string // input 2
		expected string // expected result
	}{
		{"", "", "."},
		{"root", "", "root."},
		{"root.", "", "root.."},
		{"root", "less", "root.less"},
		{"root.foo", "bar", "root.foo.bar"},
	}
	for _, tt := range joinPathTests {
		actual := JoinPath(tt.input1, tt.input2)
		c.Assert(actual, Equals, tt.expected)
	}
}
