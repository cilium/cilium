// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemovePinsInDir(t *testing.T) {
	dir := t.TempDir()

	// Mixed pins: files and nested directories.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pin1"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "pin2"), []byte("x"), 0o600))

	removed, err := removePinsInDir(dir)
	require.NoError(t, err)
	require.Equal(t, 2, removed)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)

	// Removing an already-empty dir works and reports zero.
	removed, err = removePinsInDir(dir)
	require.NoError(t, err)
	require.Equal(t, 0, removed)

	// A missing dir is not an error.
	removed, err = removePinsInDir(filepath.Join(dir, "does-not-exist"))
	require.NoError(t, err)
	require.Equal(t, 0, removed)
}
