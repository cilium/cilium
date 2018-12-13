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

package debug

import (
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type DebugTestSuite struct{}

var _ = Suite(&DebugTestSuite{})

type debugObj struct{}

func (d *debugObj) DebugStatus() string {
	return "test3"
}

func (s *DebugTestSuite) TestSubsystem(c *C) {
	sf := newStatusFunctions()
	c.Assert(sf.collectStatus(), checker.DeepEquals, StatusMap{})

	sf = newStatusFunctions()
	sf.register("foo", func() string { return "test1" })
	c.Assert(sf.collectStatus(), checker.DeepEquals, StatusMap{
		"foo": "test1",
	})

	sf.register("bar", func() string { return "test2" })
	c.Assert(sf.collectStatus(), checker.DeepEquals, StatusMap{
		"foo": "test1",
		"bar": "test2",
	})

	sf.register("bar", func() string { return "test2" })
	c.Assert(sf.collectStatus(), checker.DeepEquals, StatusMap{
		"foo": "test1",
		"bar": "test2",
	})

	sf.registerStatusObject("baz", &debugObj{})
	c.Assert(sf.collectStatus(), checker.DeepEquals, StatusMap{
		"foo": "test1",
		"bar": "test2",
		"baz": "test3",
	})
}
