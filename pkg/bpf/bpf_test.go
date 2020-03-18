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

package bpf

import (
	. "gopkg.in/check.v1"
)

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
