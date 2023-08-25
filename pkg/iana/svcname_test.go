// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iana

import (
	"testing"

	. "github.com/cilium/checkmate"
)

type IANATestSuite struct{}

var _ = Suite(&IANATestSuite{})

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

func (s *IANATestSuite) TestIsSvcName(c *C) {
	c.Assert(IsSvcName(""), Equals, false)                 // Too short
	c.Assert(IsSvcName("1234567890abcdef"), Equals, false) // Too long
	c.Assert(IsSvcName("1"), Equals, false)                // Missing letter
	c.Assert(IsSvcName("1a"), Equals, true)
	c.Assert(IsSvcName("Z"), Equals, true)
	c.Assert(IsSvcName("a9"), Equals, true)
	c.Assert(IsSvcName("a-9"), Equals, true)
	c.Assert(IsSvcName("a--9"), Equals, false) // Two consecutive dashes
	c.Assert(IsSvcName("-a9"), Equals, false)  // Begins with a dash
	c.Assert(IsSvcName("a9-"), Equals, false)  // Ends with a dash
	c.Assert(IsSvcName("a-b9-1"), Equals, true)
	c.Assert(IsSvcName("1-a-9"), Equals, true)
	c.Assert(IsSvcName("a-b-c-d-e-f"), Equals, true)
	c.Assert(IsSvcName("1-2-3-4"), Equals, false) // No letter(s)
}
