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

package main

import (
	"testing"

	"github.com/cilium/cilium/pkg/logging"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	logging.ToggleDebugLogs(true)
	TestingT(t)
}

type LibSuite struct{}

var _ = Suite(&LibSuite{})

func (l *LibSuite) TestAdvanceInput(c *C) {
	data := &[][]byte{[]byte("ABCD"), []byte("1234567890"), []byte("abcdefghij")}
	unit := 0
	offset := 0
	var bytes int

	c.Assert((*data)[unit][offset], Equals, byte('A'))

	// Advance to one byte before the end of the first slice
	bytes, unit, offset = advanceInput(3, unit, offset, data)
	c.Assert(bytes, Equals, 0)  // Had as many bytes as requested
	c.Assert(unit, Equals, 0)   // Still in the first slice
	c.Assert(offset, Equals, 3) // At the offset 3 within the first unit
	c.Assert((*data)[unit][offset], Equals, byte('D'))

	// Advance to the beginning of the next slice
	bytes, unit, offset = advanceInput(1, unit, offset, data)
	c.Assert(bytes, Equals, 0)  // Had as many bytes as requested
	c.Assert(unit, Equals, 1)   // Moved to the next slice
	c.Assert(offset, Equals, 0) // In the begining of the 2nd slice
	c.Assert((*data)[unit][offset], Equals, byte('1'))

	// Advance 11 bytes, crossing to the next slice
	bytes, unit, offset = advanceInput(11, unit, offset, data)
	c.Assert(bytes, Equals, 0)  // Had as many bytes as requested
	c.Assert(unit, Equals, 2)   // Moved to the 3rd slice
	c.Assert(offset, Equals, 1) // One past the beginning
	c.Assert((*data)[unit][offset], Equals, byte('b'))

	// Try to advance 11 bytes when only 9 remmain
	bytes, unit, offset = advanceInput(11, unit, offset, data)
	c.Assert(bytes, Equals, 2) // 2 bytes remaining
	c.Assert(unit, Equals, 3)  // All data exhausted
	c.Assert(offset, Equals, 0)
}
