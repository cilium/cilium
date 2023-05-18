// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	. "github.com/cilium/checkmate"
)

func Test(t *testing.T) { TestingT(t) }

func (s *BPFTestSuite) TestDefaultMapFlags(c *C) {
	c.Assert(GetPreAllocateMapFlags(MapTypeLPMTrie), Equals, uint32(BPF_F_NO_PREALLOC))
	c.Assert(GetPreAllocateMapFlags(MapTypeArray), Equals, uint32(0))
	c.Assert(GetPreAllocateMapFlags(MapTypeLRUHash), Equals, uint32(0))

	c.Assert(GetPreAllocateMapFlags(MapTypeHash), Equals, uint32(BPF_F_NO_PREALLOC))
	EnableMapPreAllocation()
	c.Assert(GetPreAllocateMapFlags(MapTypeHash), Equals, uint32(0))

	c.Assert(GetPreAllocateMapFlags(MapTypeLPMTrie), Equals, uint32(BPF_F_NO_PREALLOC))
	c.Assert(GetPreAllocateMapFlags(MapTypeArray), Equals, uint32(0))
	c.Assert(GetPreAllocateMapFlags(MapTypeLRUHash), Equals, uint32(0))
	DisableMapPreAllocation()
}

func (s *BPFTestSuite) TestPreallocationFlags(c *C) {
	for m := MapType(0); m < MapTypeMaximum; m++ {
		c.Assert(m.allowsPreallocation() || !m.requiresPreallocation(), Equals, true)
	}
}
