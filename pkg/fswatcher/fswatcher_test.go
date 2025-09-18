// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestWatcher(t *testing.T) {
	logger := hivetest.Logger(t)
	tmp := t.TempDir()

	var (
		data = []byte("data")

		regularFile     = filepath.Join(tmp, "file")
		regularSymlink  = filepath.Join(tmp, "symlink")
		nestedDir       = filepath.Join(tmp, "foo", "bar")
		nestedFile      = filepath.Join(nestedDir, "nested")
		directSymlink   = filepath.Join(tmp, "foo", "symlink") // will point to nestedDir
		indirectSymlink = filepath.Join(tmp, "foo", "symlink", "nested")
		targetFile      = filepath.Join(tmp, "target")
		target2         = filepath.Join(tmp, "target2")
		symlink2        = filepath.Join(tmp, "symlink2")
	)

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
				// update $tmp/file written in a previous subtest
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
				// redirect $tmp/symlink -> $tmp/file
				err := os.Remove(regularSymlink)
				require.NoError(t, err)
				err = os.Symlink(regularFile, regularSymlink)
				require.NoError(t, err)
			},
			want: []Event{
				{Name: regularSymlink, Op: Write},
			},
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
		{
			// no-op test deliberately inserted to make sure the tracked state is
			// properly updated after deletion of the events
			//
			// while writing this package, deletion was accidentally passing since it
			// was the last test and forever after reported that the same file was
			// deleted every tick.
			name: "no op",
			work: func() {},
			want: []Event{},
		},
		{
			name: "make a new symlink2",
			work: func() {
				// create a target which is not tracked anywhere
				require.NoError(t, os.WriteFile(target2, []byte("new target data"), 0777))

				// create a tracked symlink
				require.NoError(t, os.Symlink(target2, symlink2))
			},
			want: []Event{
				{Name: symlink2, Op: Create | Write},
			},
		},
		{
			name: "delete symlink",
			work: func() {
				// delete symlink not the target
				require.NoError(t, os.Remove(symlink2))
			},
			want: []Event{
				{Name: symlink2, Op: Remove},
			},
		},
		{
			name: "trailing",
			work: func() {
				// no work to make sure there are no lingering events after one more tick
			},
			want: []Event{},
		},
	}

	w, err := New(logger, []string{
		regularFile,
		regularSymlink,
		nestedFile,
		indirectSymlink,
		symlink2,
	}, WithInterval(10*time.Second)) // long enough to be irrelevant as test manually ticks
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getEventsFor(t, w, tt.work)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

// This test mimics how kubernetes mounts a secret and what happens during the update.
func TestKubernetesMount(t *testing.T) {
	logger := hivetest.Logger(t)
	tmp := t.TempDir()

	var (
		config      = filepath.Join(tmp, "config")
		dataSymlink = filepath.Join(config, "..data")
		dataOrig    = filepath.Join(config, "..2025.123")
		dataUpdated = filepath.Join(config, "..2025.456")

		key1       = "key1"
		key1Watch  = filepath.Join(config, key1)
		key1value1 = []byte("key1value1")
		key1value2 = []byte("key1value2")

		key2       = "key2"
		key2Watch  = filepath.Join(config, key2)
		key2value1 = []byte("key2value1")
	)

	cases := []struct {
		name string
		work func() // os level file operations
		want []Event
	}{
		{
			name: "create mount projection",
			work: func() {
				// $tmp
				// └── config
				// ├── ..2025.123
				// │   ├── key1
				// │   └── key2
				// ├── ..data -> $tmp/k8s-mount/config/..2025.123
				// ├── key1 -> $tmp/k8s-mount/config/..data/key1 (value1)
				// └── key2 -> $tmp/k8s-mount/config/..data/key2

				require.NoError(t, os.MkdirAll(config, 0777))
				require.NoError(t, os.MkdirAll(dataOrig, 0777))

				// config/..2025.123/key1 = key1value1
				require.NoError(t,
					os.WriteFile(
						filepath.Join(dataOrig, key1),
						key1value1, 0777,
					),
				)

				// config/..2025.123/key2 = key2value1
				require.NoError(t,
					os.WriteFile(
						filepath.Join(dataOrig, key2),
						key2value1, 0777,
					),
				)

				// config/..data -> config/..2025.123
				require.NoError(t, os.Symlink(dataOrig, dataSymlink))

				// config/key1 -> config/..data/key1
				require.NoError(t, os.Symlink(filepath.Join(dataSymlink, "key1"), key1Watch))

				// config/key2 -> config/..data/key2
				require.NoError(t, os.Symlink(filepath.Join(dataSymlink, "key2"), key2Watch))
			},
			want: []Event{
				{Name: key1Watch, Op: Create | Write},
				{Name: key2Watch, Op: Create | Write},
			},
		},
		{
			name: "update with new data",
			work: func() {
				// $tmp
				// └── config
				// ├── ..2025.456
				// │   ├── key1
				// │   └── key2
				// ├── ..data -> $tmp/k8s-mount/config/..2025.456
				// ├── key1 -> $tmp/k8s-mount/config/..data/key1 (value2)
				// └── key2 -> $tmp/k8s-mount/config/..data/key2

				// create a new data directory
				require.NoError(t, os.MkdirAll(dataUpdated, 0777))

				// rm old data dira and ..data symlink (temporarily breaking key ->
				// ..data -> ..{date} chain)
				require.NoError(t, os.RemoveAll(dataOrig))
				require.NoError(t, os.RemoveAll(dataSymlink))

				// new value for key1 -- should detect write
				// config/..2025.456/key1 = key1value2
				require.NoError(t,
					os.WriteFile(
						filepath.Join(dataUpdated, key1),
						key1value2, 0777,
					),
				)

				// same value for key2 -- no value change, but ModTime||Size should
				// still trigger a write event.
				//
				// config/..2025.456 = key2value1
				require.NoError(t,
					os.WriteFile(
						filepath.Join(dataUpdated, key2),
						key2value1, 0777,
					),
				)

				// config/..data -> config/..2025.456
				require.NoError(t, os.Symlink(dataUpdated, dataSymlink))

				// key1, key2 symlinks are not touched
			},
			want: []Event{
				{Name: key1Watch, Op: Write},
			},
		},
		{
			name: "trailing",
			work: func() {
				// no work to make sure there are no lingering events after one more tick
			},
			want: []Event{},
		},
	}

	w, err := New(logger,
		[]string{
			key1Watch,
			key2Watch,
		}, WithInterval(10*time.Second)) // long enough to be irrelevant as test manually ticks
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getEventsFor(t, w, tt.work)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestWatcherDir(t *testing.T) {
	logger := hivetest.Logger(t)
	tmp := t.TempDir()

	var (
		file1 = filepath.Join(tmp, "file1")
		dir1  = filepath.Join(tmp, "dir1")
		file2 = filepath.Join(dir1, "file2")
	)

	cases := []struct {
		name string
		work func() // os level file operations
		want []Event
	}{
		{
			name: "create file in a watched directory",
			work: func() {
				require.NoError(t, os.WriteFile(file1, []byte("data"), 0777))
			},
			want: []Event{
				{Name: file1, Op: Create | Write},
			},
		},
		{
			name: "create a subdirectory",
			work: func() {
				require.NoError(t, os.MkdirAll(dir1, 0777))
			},
			want: []Event{},
		},
		{
			name: "create file in subdirectory",
			work: func() {
				require.NoError(t, os.WriteFile(file2, []byte("more data"), 0777))
			},
			want: []Event{
				{Name: file2, Op: Create | Write},
			},
		},
		{
			name: "modify file in subdirectory",
			work: func() {
				require.NoError(t, os.WriteFile(file2, []byte("even more data"), 0777))
			},
			want: []Event{
				{Name: file2, Op: Write},
			},
		},
		{
			name: "trailing",
			work: func() {
				// no work to make sure there are no lingering events after one more tick
			},
			want: []Event{},
		},
	}

	w, err := New(logger,
		[]string{
			tmp, // watch whole tmp dir
		}, WithInterval(10*time.Second)) // long enough to be irrelevant as test manually ticks
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getEventsFor(t, w, tt.work)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

// when the watcher is created, it should not emit any events for existing directories
func TestWatcherExistingDir(t *testing.T) {
	logger := hivetest.Logger(t)
	tmp := t.TempDir()

	var (
		file1 = filepath.Join(tmp, "file1")
		file2 = filepath.Join(tmp, "file2")
	)

	// write data into the files immediately
	require.NoError(t, os.WriteFile(file1, []byte("data1"), 0777))
	require.NoError(t, os.WriteFile(file2, []byte("data2"), 0777))

	w, err := New(logger,
		[]string{
			file1,
			file2,
		}, WithInterval(10*time.Second)) // long enough to be irrelevant as test manually ticks
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })

	got, err := getEventsFor(t, w, func() {
		// update file1
		require.NoError(t, os.WriteFile(file1, []byte("data1 updated"), 0777))
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []Event{
		{Name: file1, Op: Write},
	}, got)
}

func getEventsFor(t *testing.T, w *Watcher, work func()) ([]Event, error) {
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
