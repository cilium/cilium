// Copyright 2017-2019 Authors of Cilium
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

package cmd

import (
	"archive/tar"
	"fmt"
	"io/ioutil"
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
	baseDir, err = ioutil.TempDir("", "cilium_test_bugtool_base")
	c.Assert(err, IsNil)
	tmpDir, err = ioutil.TempDir("", "cilium_test_bugtool_tmp")
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
	w := newWalker(baseDir, tmpDir, &dummyTarWriter{}, &logWrapper{c.Logf})
	c.Assert(w, NotNil)

	// Invalid paths
	invalidFile := "doesnotexist"
	err := w.walkPath(invalidFile, nil, nil)
	c.Assert(err, IsNil)
	err = w.walkPath(invalidFile, nil, fmt.Errorf("ignore me please"))
	c.Assert(err, IsNil)

	// Invalid symlink
	invalidLink := filepath.Join(baseDir, "totes_real_link")
	err = os.Symlink(invalidFile, invalidLink)
	c.Assert(err, IsNil)
	_, err = os.Stat(invalidLink)
	c.Assert(err, NotNil)
	info, err := os.Lstat(invalidLink)
	c.Assert(err, IsNil)
	err = w.walkPath(invalidLink, info, nil)
	c.Assert(err, IsNil)

	// With real file
	realFile, err := ioutil.TempFile(baseDir, "test")
	c.Assert(err, IsNil)
	info, err = os.Stat(realFile.Name())
	c.Assert(err, IsNil)
	err = w.walkPath(realFile.Name(), info, nil)
	c.Assert(err, IsNil)

	// With real link to real file
	realLink := filepath.Join(baseDir, "test_link")
	err = os.Symlink(realFile.Name(), realLink)
	c.Assert(err, IsNil)
	info, err = os.Lstat(realLink)
	c.Assert(err, IsNil)
	err = w.walkPath(realLink, info, nil)
	c.Assert(err, IsNil)

	// With directory
	nestedDir, err := ioutil.TempDir(baseDir, "nested")
	c.Assert(err, IsNil)
	info, err = os.Stat(nestedDir)
	c.Assert(err, IsNil)
	err = w.walkPath(nestedDir, info, nil)
	c.Assert(err, IsNil)
}
