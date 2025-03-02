// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatcherNew(t *testing.T) {
	cases := []struct {
		name    string                          // description of the test
		watch   []string                        // paths to watch
		actions func(evs chan<- fsnotify.Event) // actions to undertake in a test
		want    []Event                         // expected events
		check   func(t *testing.T, w *Watcher)  // any additional checks
	}{
		{
			name: "create unwatched file",
			watch: []string{
				"unwatched",
			},
			actions: func(evs chan<- fsnotify.Event) {
				evs <- fsnotify.Event{Name: "bar", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "baz", Op: fsnotify.Create}
			},
			want: nil,
		},
		{
			name: "watch a file",
			watch: []string{
				"watched",
				"watched2",
			},
			actions: func(evs chan<- fsnotify.Event) {
				evs <- fsnotify.Event{Name: "bar", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "baz", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "watched", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "watched", Op: fsnotify.Write}
			},
			want: []Event{
				{Name: "watched", Op: fsnotify.Create},
				{Name: "watched", Op: fsnotify.Write},
			},
			check: func(t *testing.T, w *Watcher) {
				require.Len(t, w.watcher.WatchList(), 1)

				// only watch the root directory once even for two files
				assert.Equal(t, ".", w.watcher.WatchList()[0])
			},
		},
		{
			name: "watch a nested file",
			watch: []string{
				"/tmp/foo/bar/nested",
			},
			actions: func(evs chan<- fsnotify.Event) {
				evs <- fsnotify.Event{Name: "/tmp/untracked", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "/tmp/foo/bar/nested", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "/tmp/foo/bar/nested", Op: fsnotify.Write}
				evs <- fsnotify.Event{Name: "/tmp/foo/bar/nested", Op: fsnotify.Remove}
			},
			want: []Event{
				{Name: "/tmp/foo/bar/nested", Op: fsnotify.Create},
				{Name: "/tmp/foo/bar/nested", Op: fsnotify.Write},
				{Name: "/tmp/foo/bar/nested", Op: fsnotify.Remove},
			},
		},
		{
			name: "delete",
			watch: []string{
				"/tmp/foo",
			},
			actions: func(evs chan<- fsnotify.Event) {
				evs <- fsnotify.Event{Name: "untracked", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "/tmp/foo", Op: fsnotify.Create}
				evs <- fsnotify.Event{Name: "untracked", Op: fsnotify.Remove}
				evs <- fsnotify.Event{Name: "/tmp/foo", Op: fsnotify.Remove}
			},
			want: []Event{
				{Name: "/tmp/foo", Op: fsnotify.Create},
				{Name: "/tmp/foo", Op: fsnotify.Remove},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.watch)
			require.NoError(t, err)
			t.Cleanup(w.Close)

			// how long to give the test to read from the channel to make sure there
			// are no unexpected events received
			timeout := 100 * time.Millisecond

			if tc.actions != nil {
				go func() {
					tc.actions(w.watcher.Events)
				}()
			}

			var got []Event
		LOOP:
			for {
				select {
				case e := <-w.Events:
					got = append(got, e)
				case err := <-w.Errors:
					t.Fatalf("unexpected error: %v", err)
				case <-time.After(timeout):
					break LOOP
				}
			}

			assert.Equal(t, tc.want, got)
			if tc.check != nil {
				tc.check(t, w)
			}
		})
	}
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
