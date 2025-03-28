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

	var data = []byte("data")
	regularFile := filepath.Join(tmp, "file")
	regularSymlink := filepath.Join(tmp, "symlink")
	nestedDir := filepath.Join(tmp, "foo", "bar")
	nestedFile := filepath.Join(nestedDir, "nested")
	directSymlink := filepath.Join(tmp, "foo", "symlink") // will point to nestedDir
	indirectSymlink := filepath.Join(tmp, "foo", "symlink", "nested")
	targetFile := filepath.Join(tmp, "target")

	cases := []struct {
		name string
		work func() // os level file operations
		want []Event
	}{
		{
			name: "create untracked dir",
			work: func() {
				// create $tmp/foo/ (this should not emit an event)
				fooDirectory := filepath.Join(tmp, "foo")
				err := os.MkdirAll(fooDirectory, 0777)
				require.NoError(t, err)
			},
			want: []Event{},
		},
		{
			name: "create and write file",
			work: func() {
				// create $tmp/file
				err := os.WriteFile(regularFile, data, 0777)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: regularFile, Op: Create | Write},
			},
		},
		{
			name: "update file",
			work: func() {
				// create $tmp/file
				err := os.WriteFile(regularFile, []byte("some new data"), 0777)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: regularFile, Op: Write},
			},
		},
		{
			name: "create symlink",
			work: func() {
				// symlink $tmp/symlink -> $tmp/target
				err := os.WriteFile(targetFile, data, 0777)
				require.NoError(t, err)
				err = os.Symlink(targetFile, regularSymlink)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: regularSymlink, Op: Create | Write},
			},
		},
		{
			name: "create nested file",
			work: func() {
				// create $tmp/foo/bar/nested
				err := os.MkdirAll(filepath.Dir(nestedFile), 0777)
				require.NoError(t, err)
				err = os.WriteFile(nestedFile, data, 0777)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: nestedFile, Op: Create | Write},
			},
		},
		{
			name: "create indirect symlink",
			work: func() {
				// symlink $tmp/foo/symlink -> $tmp/foo/bar (this will emit an event on indirectSymlink)
				err := os.Symlink(nestedDir, directSymlink)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: indirectSymlink, Op: Create | Write},
			},
		},
		{
			name: "redirect symlink",
			work: func() {
				// redirect $tmp/symlink -> $tmp/file (this will not emit an event)
				err := os.Remove(regularSymlink)
				require.NoError(t, err)
				err = os.Symlink(regularFile, regularSymlink)
				require.NoError(t, err)
			},
			want: []Event{},
		},
		{
			name: "delete file",
			work: func() {
				// delete $tmp/file (this will also emit an event on regularSymlink)
				err := os.Remove(regularFile)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: regularFile, Op: Remove},
				{Name: regularSymlink, Op: Remove},
			},
		},
	}

	w, err := New([]string{
		regularFile,
		regularSymlink,
		nestedFile,
		indirectSymlink,
	}, WithInterval(0))

	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	getEventsFor := func(work func()) ([]Event, error) {
		t.Helper()

		got := []Event{}
		var watchErr error

		ready := Event{Name: "test listener is ready"}
		done := Event{Name: "test listener is done"}

		go func() {
			t.Helper()

		LOOP:
			for {
				select {
				case event := <-w.Events:
					// sync event to make sure channel is being listened to before
					// any os operations are done otherwise on particularly fast systems the
					// events may be missed when the test is still setting up
					if event == ready {
						continue
					}

					if event == done {
						break LOOP
					}

					got = append(got, event)
				case err := <-w.Errors:
					watchErr = err
					return
				}
			}
		}()

		w.Events <- ready
		work()
		w.tick()
		w.Events <- done

		return got, watchErr
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getEventsFor(tt.work)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}
