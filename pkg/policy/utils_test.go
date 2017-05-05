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

package policy

import (
	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) TestSplitNodePath(c *C) {
	var removeRootTests = []struct {
		input     string // input
		expected1 string // expected result 1
		expected2 string // expected result 2
	}{
		{"", "", ""},
		{"root", "root", ""},
		{"root.", "root", ""},
		{"rootless..foo", "rootless.", "foo"},
		{"root.foo", "root", "foo"},
		{"foo.bar", "foo", "bar"},
		{"foo.bar.baz", "foo.bar", "baz"},
		{".bar", "", "bar"},
	}
	for _, tt := range removeRootTests {
		actual1, actual2 := SplitNodePath(tt.input)
		c.Assert(actual1, Equals, tt.expected1)
		c.Assert(actual2, Equals, tt.expected2)
	}
}

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

func (s *PolicyTestSuite) TestremoveRootPrefix(c *C) {
	var removeRootTests = []struct {
		input    string // input
		expected string // expected result
	}{
		{"", ""},
		{"root", ""},
		{"root.", ""},
		{"root.root.", "root."},
		{"rootless", "rootless"},
		{"root.foo", "foo"},
		{"root..foo", ".foo"},
		{"foo.bar", "foo.bar"},
	}
	for _, tt := range removeRootTests {
		actual := removeRootPrefix(tt.input)
		c.Assert(actual, Equals, tt.expected)
	}
}

func (s *PolicyTestSuite) TestremoveRootK8sPrefix(c *C) {
	var removeRootTests = []struct {
		input    string // input
		expected string // expected result
	}{
		{"", ""},
		{"root", ""},
		{"root.", ""},
		{"root.root.", "root."},
		{"root.root.k8s.", "root.k8s."},
		{"root.k8s.", ""},
		{"k8s.", ""},
		{"root.k8s.foo.bar", "foo.bar"},
	}
	for _, tt := range removeRootTests {
		actual := removeRootK8sPrefix(tt.input)
		c.Assert(actual, Equals, tt.expected)
	}
}
