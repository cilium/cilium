// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func TestDefaultMapFlags(t *testing.T) {
	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetMapMemoryFlags(ebpf.Hash))
	require.Equal(t, uint32(0), GetMapMemoryFlags(ebpf.LRUHash))
	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetMapMemoryFlags(ebpf.LPMTrie))
	require.Equal(t, uint32(0), GetMapMemoryFlags(ebpf.Array))

	EnableMapPreAllocation()
	require.Equal(t, uint32(0), GetMapMemoryFlags(ebpf.Hash))
	require.Equal(t, uint32(0), GetMapMemoryFlags(ebpf.LRUHash))
	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetMapMemoryFlags(ebpf.LPMTrie))
	require.Equal(t, uint32(0), GetMapMemoryFlags(ebpf.Array))
	DisableMapPreAllocation()

	EnableMapDistributedLRU()
	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetMapMemoryFlags(ebpf.Hash))
	require.Equal(t, uint32(BPF_F_NO_COMMON_LRU), GetMapMemoryFlags(ebpf.LRUHash))
	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetMapMemoryFlags(ebpf.LPMTrie))
	require.Equal(t, uint32(0), GetMapMemoryFlags(ebpf.Array))
	DisableMapDistributedLRU()
}
