// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"strings"
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type CommonSuite struct{}

var _ = check.Suite(&CommonSuite{})

func (s *CommonSuite) TestC2GoArray(c *check.C) {
	c.Assert(C2GoArray("0x0, 0x1, 0x2, 0x3"), checker.DeepEquals, []byte{0, 0x01, 0x02, 0x03})
	c.Assert(C2GoArray("0x0, 0xff, 0xff, 0xff"), checker.DeepEquals, []byte{0, 0xFF, 0xFF, 0xFF})
	c.Assert(C2GoArray("0xa, 0xbc, 0xde, 0xf1"), checker.DeepEquals, []byte{0xa, 0xbc, 0xde, 0xf1})
	c.Assert(C2GoArray("0x0"), checker.DeepEquals, []byte{0})
	c.Assert(C2GoArray(""), checker.DeepEquals, []byte{})
}

func (s *CommonSuite) TestGoArray2C(c *check.C) {
	tests := []struct {
		input  []byte
		output string
	}{
		{
			input:  []byte{0, 0x01, 0x02, 0x03},
			output: "0x0, 0x1, 0x2, 0x3",
		},
		{
			input:  []byte{0, 0xFF, 0xFF, 0xFF},
			output: "0x0, 0xff, 0xff, 0xff",
		},
		{
			input:  []byte{0xa, 0xbc, 0xde, 0xf1},
			output: "0xa, 0xbc, 0xde, 0xf1",
		},
		{
			input:  []byte{0},
			output: "0x0",
		},
		{
			input:  []byte{},
			output: "",
		},
	}

	for _, test := range tests {
		c.Assert(GoArray2C(test.input), check.Equals, test.output)
	}
}

func (s *CommonSuite) TestGetNumPossibleCPUsFromReader(c *check.C) {
	log := logging.DefaultLogger.WithField(logfields.LogSubsys, "utils-test")
	tests := []struct {
		in       string
		expected int
	}{
		{"0", 1},
		{"0-7", 8},
		{"0,2-3", 3},
		{"", 0},
		{"foobar", 0},
	}

	for _, t := range tests {
		possibleCpus := getNumPossibleCPUsFromReader(log, strings.NewReader(t.in))
		c.Assert(possibleCpus, check.Equals, t.expected)
	}

}
