// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestGetBPFUsage(t *testing.T) {
	testutils.PrivilegedTest(t)

	prefix := "_ciltest_"

	setupGetBPFUsage(t, prefix)

	usage, err := newBPFVisitor([]string{prefix + "1", prefix + "2"}).Usage()
	require.NoError(t, err)

	assert.EqualValues(t, 2, usage.programs)
	assert.EqualValues(t, 2*os.Getpagesize(), usage.programBytes) // one page per program
	assert.EqualValues(t, 1, usage.maps)
	assert.NotEqualValues(t, 0, usage.mapBytes)

	usage, err = newBPFVisitor([]string{"no_match"}).Usage()
	require.NoError(t, err)
	assert.EqualValues(t, 0, usage.programs)
	assert.EqualValues(t, 0, usage.programBytes)
	assert.EqualValues(t, 0, usage.maps)
	assert.EqualValues(t, 0, usage.mapBytes)

	usage, err = newBPFVisitor(nil).Usage()
	require.NoError(t, err)
	assert.NotEqualValues(t, 0, usage.programs)
	assert.NotEqualValues(t, 0, usage.programBytes)
	assert.NotEqualValues(t, 0, usage.maps)
	assert.NotEqualValues(t, 0, usage.mapBytes)
}

func BenchmarkGetBPFUsage(b *testing.B) {
	testutils.PrivilegedTest(b)

	prefix := "_ciltest_"
	for range 1000 {
		setupGetBPFUsage(b, prefix)
	}

	b.ResetTimer()

	for b.Loop() {
		if _, err := newBPFVisitor([]string{prefix}).Usage(); err != nil {
			b.Fatal(err)
		}
	}
}

func setupGetBPFUsage(tb testing.TB, prefix string) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	require.NoError(tb, err)

	p1, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Name: prefix + "1",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})

	require.NoError(tb, err)
	p2, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Name: prefix + "2",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	require.NoError(tb, err)

	tb.Cleanup(func() {
		m.Close()
		p1.Close()
		p2.Close()
	})
}
