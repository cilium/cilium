// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package command

import (
	"testing"

	. "github.com/cilium/checkmate"
)

func Test(t *testing.T) { TestingT(t) }

type CMDHelpersSuite struct{}

var _ = Suite(&CMDHelpersSuite{})

func (s *CMDHelpersSuite) TestDumpJSON(c *C) {
	type sampleData struct {
		ID   int
		Name string
	}

	tt := sampleData{
		ID:   1,
		Name: "test",
	}

	err := dumpJSON(tt, "")
	c.Assert(err, IsNil)

	err = dumpJSON(tt, "{.Id}")
	c.Assert(err, IsNil)

	err = dumpJSON(tt, "{{.Id}}")
	if err == nil {
		c.Fatalf("Dumpjson jsonpath no error with invalid path '%s'", err)
	}
}

func (s *CMDHelpersSuite) TestDumpYAML(c *C) {
	type sampleData struct {
		ID   int
		Name string
	}

	tt := sampleData{
		ID:   1,
		Name: "test",
	}

	err := dumpYAML(tt)
	c.Assert(err, IsNil)
}
