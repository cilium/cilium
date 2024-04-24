// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func TestDefaultMapFlags(t *testing.T) {
	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetPreAllocateMapFlags(ebpf.LPMTrie))
	require.Equal(t, uint32(0), GetPreAllocateMapFlags(ebpf.Array))
	require.Equal(t, uint32(0), GetPreAllocateMapFlags(ebpf.LRUHash))

	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetPreAllocateMapFlags(ebpf.Hash))
	EnableMapPreAllocation()
	require.Equal(t, uint32(0), GetPreAllocateMapFlags(ebpf.Hash))

	require.Equal(t, uint32(BPF_F_NO_PREALLOC), GetPreAllocateMapFlags(ebpf.LPMTrie))
	require.Equal(t, uint32(0), GetPreAllocateMapFlags(ebpf.Array))
	require.Equal(t, uint32(0), GetPreAllocateMapFlags(ebpf.LRUHash))
	DisableMapPreAllocation()
}
