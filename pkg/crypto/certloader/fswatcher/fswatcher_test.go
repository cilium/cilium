// Copyright 2020 Authors of Cilium
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

package fswatcher

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"
)

type FsWatcherTestSuite struct{}

var _ = Suite(&FsWatcherTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *FsWatcherTestSuite) TestWatcher(c *C) {
	tmp, err := ioutil.TempDir("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmp)

	regularFile := filepath.Join(tmp, "file")
	regularSymlink := filepath.Join(tmp, "symlink")
	nestedDir := filepath.Join(tmp, "foo", "bar")
	nestedFile := filepath.Join(nestedDir, "nested")
	directSymlink := filepath.Join(tmp, "foo", "symlink") // will point to nestedDir
	indirectSymlink := filepath.Join(tmp, "foo", "symlink", "nested")
	targetFile := filepath.Join(tmp, "target")

	var w *Watcher
	w, err = New([]string{
		regularFile,
		regularSymlink,
		nestedFile,
		indirectSymlink,
	})
	c.Assert(err, IsNil)
	defer w.Close()

	eventName := make(chan string)
	go func() {
		var lastName string
		for {
			select {
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				// not every file operation deterministically emits the same
				// number of events, therefore report each name only once
				if event.Name != lastName {
					eventName <- event.Name
					lastName = event.Name
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				c.Fatalf("unexpected error: %s", err)
			}
		}
	}()

	// create $tmp/foo/ (this should not emit an event)
	fooDirectory := filepath.Join(tmp, "foo")
	err = os.MkdirAll(fooDirectory, 0777)
	c.Assert(err, IsNil)

	// create $tmp/file
	var data = []byte("data")
	err = ioutil.WriteFile(regularFile, data, 0777)
	c.Assert(err, IsNil)
	c.Assert(<-eventName, Equals, regularFile)

	// symlink $tmp/symlink -> $tmp/target
	err = ioutil.WriteFile(targetFile, data, 0777)
	c.Assert(err, IsNil)
	err = os.Symlink(targetFile, regularSymlink)
	c.Assert(err, IsNil)
	c.Assert(<-eventName, Equals, regularSymlink)

	// create $tmp/foo/bar/nested
	err = os.MkdirAll(filepath.Dir(nestedFile), 0777)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(nestedFile, data, 0777)
	c.Assert(err, IsNil)
	c.Assert(<-eventName, Equals, nestedFile)

	// symlink $tmp/foo/symlink -> $tmp/foo/bar (this will emit an event on indirectSymlink)
	err = os.Symlink(nestedDir, directSymlink)
	c.Assert(err, IsNil)
	c.Assert(<-eventName, Equals, indirectSymlink)

	// redirect $tmp/symlink -> $tmp/file (this will not emit an event)
	err = os.Remove(regularSymlink)
	c.Assert(err, IsNil)
	err = os.Symlink(regularFile, regularSymlink)
	c.Assert(err, IsNil)
	select {
	case n := <-eventName:
		c.Fatalf("rewriting symlink emitted unexpected event on %q", n)
	default:
	}

	// delete $tmp/target (this will emit an event on regularSymlink)
	err = os.Remove(targetFile)
	c.Assert(err, IsNil)
	c.Assert(<-eventName, Equals, regularSymlink)
}

func (s *FsWatcherTestSuite) Test_hasParent(c *C) {
	type args struct {
		path   string
		parent string
	}
	tests := []struct {
		args args
		want bool
	}{
		{args: args{"/foo/bar", "/foo"}, want: true},

		{args: args{"/foo", "/foo/"}, want: true},
		{args: args{"/foo/", "/foo"}, want: true},
		{args: args{"/foo", "/foo/bar"}, want: false},
		{args: args{"/foo", "/foo/bar/baz"}, want: false},

		{args: args{"/foo/bar/baz/", "/foo"}, want: true},
		{args: args{"/foo/bar/baz/", "/foo/bar"}, want: true},
		{args: args{"/foo/bar/baz/", "/foo/baz"}, want: false},

		{args: args{"/foobar/baz", "/foo"}, want: false},

		{args: args{"/foo/..", "/foo"}, want: false},
		{args: args{"/foo/.", "/foo/.."}, want: true},
		{args: args{"/foo/.", "/foo"}, want: true},
		{args: args{"/foo/.", "/"}, want: true},
	}
	for _, tt := range tests {
		got := hasParent(tt.args.path, tt.args.parent)
		if got != tt.want {
			c.Fatalf("unexpected result %t for hasParent(%q, %q)", got, tt.args.path, tt.args.parent)
		}
	}
}
