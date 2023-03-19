// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type BugtoolSuite struct{}

var (
	_ = Suite(&BugtoolSuite{})

	baseDir, tmpDir string
)

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
	logf func(format string, args ...interface{})
}

func (l *logWrapper) Write(p []byte) (n int, err error) {
	l.logf("%s", p)
	return len(p), nil
}

func (b *BugtoolSuite) SetUpSuite(c *C) {
	var err error
	baseDir, err = os.MkdirTemp("", "cilium_test_bugtool_base")
	c.Assert(err, IsNil)
	tmpDir, err = os.MkdirTemp("", "cilium_test_bugtool_tmp")
	c.Assert(err, IsNil)
}

func (b *BugtoolSuite) TearDownSuite(c *C) {
	os.RemoveAll(baseDir)
	os.RemoveAll(tmpDir)
}

// TestWalkPath tests that with various different error types, we can safely
// back out and continue with the filepath walk. This allows gathering of other
// information in a bugtool run when there's an issue with a particular file.
func (b *BugtoolSuite) TestWalkPath(c *C) {
	w := NewWalker(baseDir, tmpDir, &dummyTarWriter{}, &logWrapper{c.Logf})
	c.Assert(w, NotNil)

	// Invalid paths
	invalidFile := "doesnotexist"
	err := w.WalkPath(invalidFile, nil, nil)
	c.Assert(err, IsNil)
	err = w.WalkPath(invalidFile, nil, fmt.Errorf("ignore me please"))
	c.Assert(err, IsNil)

	// Invalid symlink
	invalidLink := filepath.Join(baseDir, "totes_real_link")
	err = os.Symlink(invalidFile, invalidLink)
	c.Assert(err, IsNil)
	_, err = os.Stat(invalidLink)
	c.Assert(err, NotNil)
	info, err := os.Lstat(invalidLink)
	c.Assert(err, IsNil)
	err = w.WalkPath(invalidLink, info, nil)
	c.Assert(err, IsNil)

	// With real file
	realFile, err := os.CreateTemp(baseDir, "test")
	c.Assert(err, IsNil)
	info, err = os.Stat(realFile.Name())
	c.Assert(err, IsNil)
	err = w.WalkPath(realFile.Name(), info, nil)
	c.Assert(err, IsNil)

	// With real link to real file
	realLink := filepath.Join(baseDir, "test_link")
	err = os.Symlink(realFile.Name(), realLink)
	c.Assert(err, IsNil)
	info, err = os.Lstat(realLink)
	c.Assert(err, IsNil)
	err = w.WalkPath(realLink, info, nil)
	c.Assert(err, IsNil)

	// With directory
	nestedDir, err := os.MkdirTemp(baseDir, "nested")
	c.Assert(err, IsNil)
	info, err = os.Stat(nestedDir)
	c.Assert(err, IsNil)
	err = w.WalkPath(nestedDir, info, nil)
	c.Assert(err, IsNil)
}
