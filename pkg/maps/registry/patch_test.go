// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
)

func TestMapSpecPatch(t *testing.T) {
	spec := &ebpf.MapSpec{
		MaxEntries: 1024,
		ValueSize:  4096,
		Flags:      unix.BPF_F_NO_PREALLOC,
		InnerMap: &ebpf.MapSpec{
			MaxEntries: 256,
			ValueSize:  8,
			Flags:      0,
		},
	}

	patch := newMapSpecPatch(spec)
	mod := patch.copy()

	assert.Equal(t, spec.MaxEntries, mod.MaxEntries)
	assert.Equal(t, spec.ValueSize, mod.ValueSize)
	assert.Equal(t, spec.Flags, mod.Flags)
	require.NotNil(t, mod.InnerMap)
	assert.Equal(t, spec.InnerMap.MaxEntries, mod.InnerMap.MaxEntries)
	assert.Equal(t, spec.InnerMap.ValueSize, mod.InnerMap.ValueSize)
	assert.Equal(t, spec.InnerMap.Flags, mod.InnerMap.Flags)

	mod.MaxEntries = 2048
	mod.ValueSize = 8192
	mod.Flags = 0
	mod.InnerMap.MaxEntries = 512
	mod.InnerMap.ValueSize = 16
	mod.InnerMap.Flags = unix.BPF_F_NO_PREALLOC

	diff := patch.diff(mod)
	assert.Contains(t, diff, "MaxEntries: 1024 -> 2048")
	assert.Contains(t, diff, "ValueSize: 4096 -> 8192")
	assert.Contains(t, diff, "Flags: 1 -> 0")
	assert.Contains(t, diff, "InnerMap: {MaxEntries: 256 -> 512, ValueSize: 8 -> 16, Flags: 0 -> 1}")

	mod.Apply(spec)
	assert.Equal(t, uint32(2048), spec.MaxEntries)
	assert.Equal(t, uint32(8192), spec.ValueSize)
	assert.Equal(t, uint32(0), spec.Flags)
	require.NotNil(t, spec.InnerMap)
	assert.Equal(t, uint32(512), spec.InnerMap.MaxEntries)
	assert.Equal(t, uint32(16), spec.InnerMap.ValueSize)
	assert.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), spec.InnerMap.Flags)
}
