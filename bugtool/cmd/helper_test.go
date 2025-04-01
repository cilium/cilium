// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type testStrings struct {
	input  string
	output string
}

type dummyTarWriter struct{}

func (t *dummyTarWriter) Write(p []byte) (n int, err error) {
	// Ignore / discard all output.
	return len(p), nil
}

func (t *dummyTarWriter) WriteHeader(h *tar.Header) error {
	// Ignore / discard all output.
	return nil
}

type logWrapper struct {
	logf func(format string, args ...any)
}

func (l *logWrapper) Write(p []byte) (n int, err error) {
	l.logf("%s", p)
	return len(p), nil
}

// TestWalkPath tests that with various different error types, we can safely
// back out and continue with the filepath walk. This allows gathering of other
// information in a bugtool run when there's an issue with a particular file.
func TestWalkPath(t *testing.T) {
	baseDir, tmpDir := t.TempDir(), t.TempDir()

	w := newWalker(baseDir, tmpDir, &dummyTarWriter{}, &logWrapper{t.Logf})
	require.NotNil(t, w)

	// Invalid paths
	invalidFile := "doesnotexist"
	err := w.walkPath(invalidFile, nil, nil)
	require.NoError(t, err)
	err = w.walkPath(invalidFile, nil, fmt.Errorf("ignore me please"))
	require.NoError(t, err)

	// Invalid symlink
	invalidLink := filepath.Join(baseDir, "totes_real_link")
	err = os.Symlink(invalidFile, invalidLink)
	require.NoError(t, err)
	_, err = os.Stat(invalidLink)
	require.Error(t, err)
	info, err := os.Lstat(invalidLink)
	require.NoError(t, err)
	err = w.walkPath(invalidLink, info, nil)
	require.NoError(t, err)

	// With real file
	realFile, err := os.CreateTemp(baseDir, "test")
	require.NoError(t, err)
	info, err = os.Stat(realFile.Name())
	require.NoError(t, err)
	err = w.walkPath(realFile.Name(), info, nil)
	require.NoError(t, err)

	// With real link to real file
	realLink := filepath.Join(baseDir, "test_link")
	err = os.Symlink(realFile.Name(), realLink)
	require.NoError(t, err)
	info, err = os.Lstat(realLink)
	require.NoError(t, err)
	err = w.walkPath(realLink, info, nil)
	require.NoError(t, err)

	// With directory
	nestedDir, err := os.MkdirTemp(baseDir, "nested")
	require.NoError(t, err)
	info, err = os.Stat(nestedDir)
	require.NoError(t, err)
	err = w.walkPath(nestedDir, info, nil)
	require.NoError(t, err)
}

// TestHashEncryptionKeys tests proper hashing of keys. Lines in which `auth` or
// other relevant pattern are found but not the hexadecimal keys are intentionally
// redacted from the output to avoid accidental leaking of keys.
func TestHashEncryptionKeys(t *testing.T) {
	testdata := []testStrings{
		{
			// `auth` and hexa string
			input:  "<garbage> auth foo bar 0x123456af baz",
			output: "<garbage> auth foo bar [hash:21d466b493f5c133edc008ee375e849fe5babb55d31550c25b993d151038c8a8] baz",
		},
		{
			// `auth` but no hexa string
			input:  "<garbage> auth foo bar ###23456af baz",
			output: "[redacted]",
		},
		{
			// `enc` and hexa string
			input:  "<garbage> enc foo bar 0x123456af baz",
			output: "<garbage> enc foo bar [hash:21d466b493f5c133edc008ee375e849fe5babb55d31550c25b993d151038c8a8] baz",
		},
		{
			// nothing
			input:  "<garbage> xxxx foo bar 0x123456af baz",
			output: "<garbage> xxxx foo bar 0x123456af baz",
		},
	}

	for _, v := range testdata {
		modifiedString := hashEncryptionKeys([]byte(v.input))
		require.Equal(t, string(modifiedString), v.output)
	}
}
