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
	realFile, err := os.CreateTemp(baseDir, "test")
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
	nestedDir, err := os.MkdirTemp(baseDir, "nested")
	c.Assert(err, IsNil)
	info, err = os.Stat(nestedDir)
	c.Assert(err, IsNil)
	err = w.walkPath(nestedDir, info, nil)
	c.Assert(err, IsNil)
}

// TestHashEncryptionKeys tests proper hashing of keys. Lines in which `auth` or
// other relevant pattern are found but not the hexadecimal keys are intentionally
// redacted from the output to avoid accidental leaking of keys.
func (b *BugtoolSuite) TestHashEncryptionKeys(c *C) {
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
		modifiedString := hashEncryptionKeys(v.input)
		c.Assert(modifiedString, Equals, v.output)
	}
}
