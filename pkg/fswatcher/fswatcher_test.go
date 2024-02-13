// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWatcher(t *testing.T) {
	tmp := t.TempDir()

	regularFile := filepath.Join(tmp, "file")
	regularSymlink := filepath.Join(tmp, "symlink")
	nestedDir := filepath.Join(tmp, "foo", "bar")
	nestedFile := filepath.Join(nestedDir, "nested")
	directSymlink := filepath.Join(tmp, "foo", "symlink") // will point to nestedDir
	indirectSymlink := filepath.Join(tmp, "foo", "symlink", "nested")
	targetFile := filepath.Join(tmp, "target")

	w, err := New([]string{
		regularFile,
		regularSymlink,
		nestedFile,
		indirectSymlink,
	})
	require.NoError(t, err)
	defer w.Close()

	var lastName string
	assertEventName := func(name string) {
		t.Helper()

		for {
			select {
			case event := <-w.Events:
				// not every file operation deterministically emits the same
				// number of events, therefore report each name only once
				if event.Name != lastName {
					require.Equal(t, name, event.Name)
					lastName = event.Name
					return
				}
			case err := <-w.Errors:
				t.Fatalf("unexpected error: %s", err)
			}
		}
	}

	// create $tmp/foo/ (this should not emit an event)
	fooDirectory := filepath.Join(tmp, "foo")
	err = os.MkdirAll(fooDirectory, 0777)
	require.NoError(t, err)

	// create $tmp/file
	var data = []byte("data")
	err = os.WriteFile(regularFile, data, 0777)
	require.NoError(t, err)
	assertEventName(regularFile)

	// symlink $tmp/symlink -> $tmp/target
	err = os.WriteFile(targetFile, data, 0777)
	require.NoError(t, err)
	err = os.Symlink(targetFile, regularSymlink)
	require.NoError(t, err)
	assertEventName(regularSymlink)

	// create $tmp/foo/bar/nested
	err = os.MkdirAll(filepath.Dir(nestedFile), 0777)
	require.NoError(t, err)
	err = os.WriteFile(nestedFile, data, 0777)
	require.NoError(t, err)
	assertEventName(nestedFile)

	// symlink $tmp/foo/symlink -> $tmp/foo/bar (this will emit an event on indirectSymlink)
	err = os.Symlink(nestedDir, directSymlink)
	require.NoError(t, err)
	assertEventName(indirectSymlink)

	// redirect $tmp/symlink -> $tmp/file (this will not emit an event)
	err = os.Remove(regularSymlink)
	require.NoError(t, err)
	err = os.Symlink(regularFile, regularSymlink)
	require.NoError(t, err)
	select {
	case n := <-w.Events:
		t.Fatalf("rewriting symlink emitted unexpected event on %q", n)
	default:
	}

	// delete $tmp/target (this will emit an event on regularSymlink)
	err = os.Remove(targetFile)
	require.NoError(t, err)
	assertEventName(regularSymlink)
}

func TestHasParent(t *testing.T) {
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
			t.Fatalf("unexpected result %t for hasParent(%q, %q)", got, tt.args.path, tt.args.parent)
		}
	}
}
