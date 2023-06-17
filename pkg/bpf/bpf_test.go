// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"

	. "github.com/cilium/checkmate"
)

func Test(t *testing.T) { TestingT(t) }

func (s *BPFTestSuite) TestDefaultMapFlags(c *C) {
	c.Assert(GetPreAllocateMapFlags(ebpf.LPMTrie), Equals, uint32(BPF_F_NO_PREALLOC))
	c.Assert(GetPreAllocateMapFlags(ebpf.Array), Equals, uint32(0))
	c.Assert(GetPreAllocateMapFlags(ebpf.LRUHash), Equals, uint32(0))

	c.Assert(GetPreAllocateMapFlags(ebpf.Hash), Equals, uint32(BPF_F_NO_PREALLOC))
	EnableMapPreAllocation()
	c.Assert(GetPreAllocateMapFlags(ebpf.Hash), Equals, uint32(0))

	c.Assert(GetPreAllocateMapFlags(ebpf.LPMTrie), Equals, uint32(BPF_F_NO_PREALLOC))
	c.Assert(GetPreAllocateMapFlags(ebpf.Array), Equals, uint32(0))
	c.Assert(GetPreAllocateMapFlags(ebpf.LRUHash), Equals, uint32(0))
	DisableMapPreAllocation()
}
