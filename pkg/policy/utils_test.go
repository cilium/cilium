// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package policy

import (
	. "gopkg.in/check.v1"
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
