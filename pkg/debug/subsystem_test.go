// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

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
