// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/time"
)

// Event closely resembles what fsnotify.Event provided
type Event struct {
	// Path to the file or directory.
	//
	// Paths are relative to the input; for example with Add("dir") the Name
	// will be set to "dir/file" if you create that file, but if you use
	// Add("/path/to/dir") it will be "/path/to/dir/file".
	Name string

	// File operation that triggered the event.
	//
	// This is a bitmask and some systems may send multiple operations at once.
	// Use the Event.Has() method instead of comparing with ==.
	Op Op
}

// Op describes a set of file operations.
type Op uint32

// Subset from fsnotify
const (
	// A new pathname was created.
	Create Op = 1 << iota

	// The pathname was written to; this does *not* mean the write has finished,
	// and a write can be followed by more writes.
	Write

	// The path was removed; any watches on it will be removed. Some "remove"
	// operations may trigger a Rename if the file is actually moved (for
	// example "remove to trash" is often a rename).
	Remove
)

// Has reports if this operation has the given operation.
func (o Op) Has(h Op) bool { return o&h != 0 }

// Has reports if this event has the given operation.
func (e Event) Has(op Op) bool { return e.Op.Has(op) }

// Watcher implements a file polling mechanism which can track non-existing
// files and emit creation events for them. All files which are supposed to be
// tracked need to passed to the New constructor.
//  1. If the file already exists, the watcher will emit write, chmod, remove
//     and rename events for the file (same as fsnotify).
//  2. If the file does not yet exist, then the Watcher makes sure to watch
//     the appropriate parent folder instead. Once the file is created, this
//     watcher will emit a creation event for the tracked file and enter
//     case 1.
//  3. If the file already exists, but is removed, then a remove event is
//     emitted and we enter case 2.
//
// Special care has to be taken around symlinks. Support for symlink is
// limited, but it supports the following cases in order to support
// Kubernetes volume mounts:
//  1. If the tracked file is a symlink, then the watcher will emit write,
//     chmod, remove and rename events for the *target* of the symlink.
//  2. If a tracked file is a symlink and the symlink target is removed,
//     then the remove event is emitted and the watcher tries to re-resolve
//     the symlink target. If the new target exists, a creation event is
//     emitted and we enter case 1). If the new target does not exist, an
//     error is emitted and the path will not be watched anymore.
//
// Most notably, if a tracked file is a symlink, any update of the symlink
// itself does not emit an event. Only if the target of the symlink observes
// an event is the symlink re-evaluated.
type Watcher struct {
	// Events is used to signal changes to any of the tracked files. It is
	// guaranteed that Event.Name will always match one of the file paths
	// passed in trackedFiles to the constructor. This channel is unbuffered
	// and must be read by the consumer to avoid deadlocks.
	Events chan Event
	// Errors reports any errors which may occur while watching. This channel
	// is unbuffered and must be read by the consumer to avoid deadlocks.
	Errors chan error

	tracked map[string]state // tracking state

	// control the interval at which the watcher checks for changes
	interval time.Duration
	ticker   <-chan time.Time

	// stop channel used to indicate shutdown
	stop chan struct{}
}

type state struct {
	path string      // tracked path as asked by the user
	info os.FileInfo // lstat info of _this_ path, even if symlink

	target     string      // target path, only applicable to symlinks
	targetInfo os.FileInfo // target info, only applicable to symlinks
}

// Option to configure the Watcher
type Option func(*Watcher)

// WithInterval sets the interval at which the Watcher checks for changes
func WithInterval(d time.Duration) Option {
	return func(w *Watcher) {
		w.interval = d
	}
}

// New creates a new Watcher which watches all trackedFile paths (they do not
// need to exist yet).
func New(trackedFiles []string, options ...Option) (*Watcher, error) {
	// sane default that is configurable via WithInterval depending on the use case
	defaultInterval := 5 * time.Second
	if testing.Testing() {
		// in a testing situation, refresh info much much faster to speed things up
		defaultInterval = 10 * time.Millisecond
	}

	w := &Watcher{
		Events:   make(chan Event),
		Errors:   make(chan error),
		stop:     make(chan struct{}),
		interval: defaultInterval,
	}

	// make a map of tracked files and assign them all empty state at the start
	tracked := make(map[string]state, len(trackedFiles))
	for _, f := range trackedFiles {
		tracked[f] = state{path: f}
	}
	w.tracked = tracked

	for _, option := range options {
		option(w)
	}

	if w.interval != 0 {
		w.ticker = time.Tick(w.interval)
	}
	go w.loop()

	return w, nil
}

func (w *Watcher) Close() {
	close(w.stop)
}

func (w *Watcher) loop() {
	for {
		select {
		case <-w.ticker:
			w.tick()
		case <-w.stop:
			return
		}
	}
}

func (w *Watcher) tick() {
	for _, oldState := range w.tracked {
		path := oldState.path
		oldInfo := oldState.info
		newState := state{path: oldState.path}

		// os.Stat follows symlinks, os.Lstat doesn't
		info, err := os.Lstat(path)
		newState.info = info

		if os.IsNotExist(err) {
			// if the path does not exist, check if it existed before because if it
			// did -- issue a deletion event
			if oldState.info != nil {
				// this file was deleted
				w.sendEvent(Event{
					Name: path,
					Op:   Remove,
				})
			}

			// the path doesn't exist, and it didn't exist before -- ignore for now
			continue
		}

		// some other type of error encountered while doing Lstat
		if err != nil {
			w.sendError(err)
			continue
		}

		// symlinks are handled a little bit differntly
		if info != nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(oldState.path)

			// unclear if symlink target resolution error is ok to swallow here
			if err != nil {
				continue
			}

			// NOTE: unclear if Stat or Lstat should be used here. Using stat to deal
			// with cascading symlinks but as more test cases are added, perhaps this
			// will need to be changed.
			targetInfo, err := os.Stat(target)

			// os.Stat on a symlink returns fs.PathError and not an os.ErrNotExist
			var pathError *fs.PathError
			if errors.As(err, &pathError) {
				if oldState.targetInfo != nil {
					w.sendEvent(Event{
						Name: path,
						Op:   Remove,
					})
				}
			} else if err != nil {
				w.sendError(err)
			}

			// haven't seen info for this track path before -- issue a creation
			if oldState.targetInfo == nil {
				op := Create

				// issue Create&Write if the file has data
				if info.Size() > 0 {
					op |= Write
				}

				w.sendEvent(Event{
					Name: path, // note event uses symlink name, not target
					Op:   op,
				})
			}

			// update info on the symlink target
			newState.target = target
			newState.targetInfo = targetInfo
		} else {
			// haven't seen info for this track path before -- issue a creation
			if oldState.info == nil {
				op := Create

				// issue Create&Write if the file has data
				if info.Size() > 0 {
					op |= Write
				}

				// this is a new file
				w.sendEvent(Event{
					Name: path,
					Op:   op,
				})
			} else if info.ModTime() != oldInfo.ModTime() || info.Size() != oldInfo.Size() {
				w.sendEvent(Event{
					Name: path,
					Op:   Write,
				})
			}
		}

		w.tracked[oldState.path] = newState
	}
}

func (w *Watcher) sendEvent(e Event) {
	select {
	case w.Events <- e:
	case <-w.stop:
	}
}

func (w *Watcher) sendError(err error) {
	select {
	case w.Errors <- err:
	case <-w.stop:
	}
}
