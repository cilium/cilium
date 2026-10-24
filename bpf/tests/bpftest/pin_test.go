// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpftests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestPinCollectionExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "keep")
	require.NoError(t, os.WriteFile(sentinel, []byte("keep"), 0600))
	require.ErrorIs(t, pinCollection(nil, dir), os.ErrExist)
	require.FileExists(t, sentinel)
}

func TestPrivilegedPinCollection(t *testing.T) {
	testutils.PrivilegedTest(t)
	root := testutils.TempBPFFS(t)
	for _, name := range []string{"first", "second"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			coll := newPinTestCollection(t)
			dir := filepath.Join(root, name)
			require.NoError(t, coll.Maps[".data"].Put(uint32(0), uint32(42)))
			require.NoError(t, coll.Maps["_data"].Put(uint32(0), uint32(99)))
			require.NoError(t, pinCollection(coll, dir))
			coll.Close()

			m, err := ebpf.LoadPinnedMap(filepath.Join(dir, "maps", "-data"), nil)
			require.NoError(t, err)
			t.Cleanup(func() { m.Close() })
			var value uint32
			require.NoError(t, m.Lookup(uint32(0), &value))
			require.Equal(t, uint32(42), value)
			other, err := ebpf.LoadPinnedMap(filepath.Join(dir, "maps", "_data"), nil)
			require.NoError(t, err)
			t.Cleanup(func() { other.Close() })
			require.NoError(t, other.Lookup(uint32(0), &value))
			require.Equal(t, uint32(99), value)

			prog, err := ebpf.LoadPinnedProgram(filepath.Join(dir, "programs", "-data"), nil)
			require.NoError(t, err)
			t.Cleanup(func() { prog.Close() })
			ret, _, err := prog.Test(make([]byte, 64))
			require.NoError(t, err)
			require.Equal(t, uint32(7), ret)

			require.NoError(t, os.RemoveAll(dir))
			_, err = ebpf.LoadPinnedMap(filepath.Join(dir, "maps", "-data"), nil)
			require.ErrorIs(t, err, os.ErrNotExist)
			_, err = ebpf.LoadPinnedProgram(filepath.Join(dir, "programs", "-data"), nil)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestPrivilegedPinCollectionRollback(t *testing.T) {
	testutils.PrivilegedTest(t)
	root := testutils.TempBPFFS(t)
	coll := newPinTestCollection(t)
	require.NoError(t, coll.Programs[".data"].Close())
	dir := filepath.Join(root, "failed")
	require.Error(t, pinCollection(coll, dir))
	require.NoDirExists(t, dir)
	// A pinning failure must not close objects still owned by the caller.
	require.NoError(t, coll.Maps[".data"].Put(uint32(0), uint32(42)))
}

func newPinTestCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	coll, err := ebpf.NewCollection(&ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			".data": {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			"_data": {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			".data": {
				Type: ebpf.SocketFilter, License: "GPL",
				Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 7), asm.Return()},
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(coll.Close)
	return coll
}
