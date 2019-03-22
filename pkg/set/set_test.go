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

package set

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SetTestSuite struct{}

var _ = Suite(&SetTestSuite{})

func (s *SetTestSuite) TestSubset(c *C) {
	testCasesTrue := []bool{
		Subset(
			[]string{"foo", "bar"},
			[]string{"foo", "bar", "baz"},
		),
		Subset(
			[]string{"foo", "bar"},
			[]string{"foo", "bar"},
		),
	}
	testCasesFalse := []bool{
		Subset(
			[]string{"foo", "bar"},
			[]string{"foo", "baz"},
		),
		Subset(
			[]string{"baz"},
			[]string{"foo", "bar"},
		),
		Subset(
			[]string{"foo", "foo", "bar"},
			[]string{"foo", "bar"},
		),
		Subset(
			[]string{"foo", "foo", "foo", "bar", "bar"},
			[]string{"foo", "foo", "bar"},
		),
	}
	for _, isSubset := range testCasesTrue {
		c.Assert(isSubset, Equals, true)
	}
	for _, isSubset := range testCasesFalse {
		c.Assert(isSubset, Equals, false)
	}
}
