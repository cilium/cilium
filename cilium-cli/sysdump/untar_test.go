// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTarGz(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	src := filepath.Join(t.TempDir(), "archive.tar.gz")
	require.NoError(t, os.WriteFile(src, buf.Bytes(), 0644))
	return src
}

func TestUntar(t *testing.T) {
	t.Run("extracts regular files under the top directory", func(t *testing.T) {
		src := writeTarGz(t, map[string]string{"top/sub/file.txt": "ok"})
		dst := t.TempDir()
		require.NoError(t, untar(src, dst))

		got, err := os.ReadFile(filepath.Join(dst, "sub", "file.txt"))
		require.NoError(t, err)
		assert.Equal(t, "ok", string(got))
	})

	t.Run("rejects entries that escape the destination", func(t *testing.T) {
		// removeTopDirectory turns "top/../escape.txt" into "../escape.txt",
		// which would resolve outside dst.
		src := writeTarGz(t, map[string]string{"top/../escape.txt": "owned"})
		root := t.TempDir()
		dst := filepath.Join(root, "out")
		require.NoError(t, os.MkdirAll(dst, 0755))

		assert.Error(t, untar(src, dst))
		_, err := os.Stat(filepath.Join(root, "escape.txt"))
		assert.True(t, os.IsNotExist(err), "no file should be written outside dst")
	})
}
