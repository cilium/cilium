// Copyright 2018 Authors of Cilium
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

package files

import (
	"io/ioutil"
	"os"
	"testing"

	. "gopkg.in/check.v1"
)

const (
	testFileName = "/tmp/cilium-test-file"
	copyFileName = "/tmp/cilium-test-copy"
)

// Hook up gocheck into the "go test" runner.
type FilesSuite struct{}

var _ = Suite(&FilesSuite{})

func Test(t *testing.T) { TestingT(t) }

func (s *FilesSuite) TestFileWithCleanupEmpty(c *C) {
	f, err := ioutil.TempFile("", "with-cleanup-empty")
	c.Assert(err, IsNil)
	defer os.Remove(f.Name())

	fwc := &FileWithCleanup{n: 0, File: f}
	err = fwc.Sync()
	c.Assert(err, IsNil)
	err = fwc.Close()
	c.Assert(err, IsNil)

	_, err = os.Stat(f.Name())
	c.Assert(err, ErrorMatches, "*.no such file or directory")
}

func (s *FilesSuite) TestFileWithCleanupNotEmpty(c *C) {
	f, err := ioutil.TempFile("", "with-cleanup-not-empty")
	c.Assert(err, IsNil)
	defer os.Remove(f.Name())

	fwc := &FileWithCleanup{n: 0, File: f}

	n, err := fwc.WriteString("foo")
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)
	c.Assert(fwc.n, Equals, 3)

	n, err = fwc.WriteString("bar")
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)
	c.Assert(fwc.n, Equals, 6)

	err = fwc.Sync()
	c.Assert(err, IsNil)
	err = fwc.Close()
	c.Assert(err, IsNil)

	info, err := os.Stat(f.Name())
	c.Assert(err, IsNil)
	c.Assert(info.Size(), Equals, int64(6))
}

func (s *FilesSuite) TestOpenOrCreate(c *C) {
	fwc, err := OpenOrCreate(testFileName)
	c.Assert(err, IsNil)
	defer os.Remove(testFileName)

	n, err := fwc.WriteString("foo")
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)

	err = fwc.Sync()
	c.Assert(err, IsNil)
	err = fwc.Close()
	c.Assert(err, IsNil)

	info, err := os.Stat(testFileName)
	c.Assert(err, IsNil)
	c.Assert(info.Size(), Equals, int64(3))
}

func (s *FilesSuite) TestOpenOrCreateAlreadyExisting(c *C) {
	f, err := ioutil.TempFile("", "open-or-create")
	c.Assert(err, IsNil)
	defer os.Remove(f.Name())

	n, err := f.WriteString("foo")
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)

	err = f.Sync()
	c.Assert(err, IsNil)
	err = f.Close()
	c.Assert(err, IsNil)

	info, err := os.Stat(f.Name())
	c.Assert(err, IsNil)
	c.Assert(info.Size(), Equals, int64(3))

	fwc, err := OpenOrCreate(f.Name())
	c.Assert(err, IsNil)

	n, err = fwc.WriteString("bar")
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)

	err = fwc.Sync()
	c.Assert(err, IsNil)
	err = fwc.Close()
	c.Assert(err, IsNil)

	info, err = os.Stat(f.Name())
	c.Assert(err, IsNil)
	c.Assert(info.Size(), Equals, int64(3))
}

func (s *FilesSuite) TestCopy(c *C) {
	err := ioutil.WriteFile(testFileName, []byte("foobar"), 0644)
	c.Assert(err, IsNil)
	err = Copy(testFileName, copyFileName)
	c.Assert(err, IsNil)
	_, err = os.Stat(copyFileName)
	c.Assert(err, IsNil)

	os.Remove(testFileName)
	os.Remove(copyFileName)
}
