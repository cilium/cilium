// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LibSuite struct{}

var _ = Suite(&LibSuite{})

func (l *LibSuite) TestAdvanceInput(c *C) {
	input := [][]byte{[]byte("ABCD"), []byte("1234567890"), []byte("abcdefghij")}

	c.Assert(input[0][0], Equals, byte('A'))
	c.Assert(len(input), Equals, 3) // Three slices in input

	// Advance to one byte before the end of the first slice
	input = advanceInput(input, 3)
	c.Assert(len(input), Equals, 3)    // Still in the first slice
	c.Assert(len(input[0]), Equals, 1) // One byte left in the first slice
	c.Assert(input[0][0], Equals, byte('D'))

	// Advance to the beginning of the next slice
	input = advanceInput(input, 1)
	c.Assert(len(input), Equals, 2) // Moved to the next slice
	c.Assert(input[0][0], Equals, byte('1'))

	// Advance 11 bytes, crossing to the next slice
	input = advanceInput(input, 11)
	c.Assert(len(input), Equals, 1) // Moved to the 3rd slice
	c.Assert(input[0][0], Equals, byte('b'))

	// Try to advance 11 bytes when only 9 remmain
	input = advanceInput(input, 11)
	c.Assert(len(input), Equals, 0) // All data exhausted

	// Try advance on an empty slice
	input = advanceInput(input, 1)
	c.Assert(len(input), Equals, 0)
}
