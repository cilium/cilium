// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"hash/fnv"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// how often tracked targets are checked for changes by default
	defaultInterval = 5 * time.Second

	// when fswatcher detects that it runs in a test, it will poll the filesystem
	// more frequently
	testInterval = 50 * time.Millisecond
)

// Event closely resembles what fsnotify.Event provided
type Event struct {
	// Path to the file or directory.
	Name string

	// File operation that triggered the event.
	//
	// This is a bitmask and some systems may send multiple operations at once.
	// Use the Event.Has() method instead of comparing with ==.
	Op Op
}

// Op describes a set of file operations.
type Op uint

// Subset from fsnotify
const (
	// A new pathname was created.
	Create Op = 1 << iota

	// The pathname was written to; this does *not* mean the write has finished,
	// and a write can be followed by more writes.
	Write

	// The path was removed
	Remove
)

// Has reports if this operation has the given operation.
func (o Op) Has(h Op) bool { return o&h != 0 }

// Has reports if this event has the given operation.
func (e Event) Has(op Op) bool { return e.Op.Has(op) }

// Watcher implements a file polling mechanism which can track non-existing
// files and emit creation events for them. All files which are supposed to be
// tracked need to passed to the New constructor.
//
// When a directory is passed in as a tracked file, the watcher will watch all
// the files inside that directory, including recursion into any subdirectories.
//
// One of the primary use cases for the watcher is tracking kubernetes projected
// secrets which create a maze of symlinks. It is safe to watch symlink targets
// as they are properly resolved, even in the case of multiple symlinks chained
// together. Only the content of the final destination is considered when
// issuing Write events.
type Watcher struct {
	logger *slog.Logger

	// Events is used to signal changes to any of the tracked files. It is
	// guaranteed that Event.Name will always match one of the file paths
	// passed in trackedFiles to the constructor. This channel is unbuffered
	// and must be read by the consumer to avoid deadlocks.
	Events chan Event
	// Errors reports any errors which may occur while watching. This channel
	// is unbuffered and must be read by the consumer to avoid deadlocks.
	Errors chan error

	tracked map[string]state // tracking state
	silent  atomic.Bool      // track updates but do not send notifications

	// control the interval at which the watcher checks for changes
	interval time.Duration
	ticker   <-chan time.Time

	// stop channel used to indicate shutdown
	stop chan struct{}
	wg   sync.WaitGroup
}

type state struct {
	path  string      // tracked path as asked by the user
	info  os.FileInfo // stat info of the file, or the target if symlink
	sum64 uint64      // checksum of the file, or the target if symlink
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
func New(defaultLogger *slog.Logger, trackedFiles []string, options ...Option) (*Watcher, error) {
	interval := defaultInterval
	if testing.Testing() {
		interval = testInterval
	}

	w := &Watcher{
		logger:   defaultLogger.With(logfields.LogSubsys, "fswatcher"),
		Events:   make(chan Event),
		Errors:   make(chan error),
		stop:     make(chan struct{}),
		interval: interval,
		silent:   atomic.Bool{},
	}

	for _, option := range options {
		option(w)
	}

	// make a map of tracked files and assign them all empty state at the start
	tracked := make(map[string]state, len(trackedFiles))
	for _, f := range trackedFiles {
		tracked[f] = state{path: f}
	}
	w.tracked = tracked

	// do the initial discovery of the state of tracked files in silent mode and
	// only issue notifications afterwards.
	w.silent.Store(true)
	w.tick()
	w.silent.Store(false)

	w.ticker = time.Tick(w.interval)
	w.wg.Add(1)
	go w.loop()

	return w, nil
}

func (w *Watcher) Close() {
	close(w.stop)
	w.wg.Wait()
}

func (w *Watcher) loop() {
	defer w.wg.Done()

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
	// get all the paths that are currently known and are being tracked and visit
	// them in order. It's done this way because the `w.tracked` map can be
	// modified as new directories are discovered.
	var order []string
	for path := range w.tracked {
		order = append(order, path)
	}

	idx := -1 // start out of bounds because idx++ is done at the start of the loop
	for {
		idx++
		if idx >= len(order) || idx < 0 {
			break
		}

		path := order[idx]
		oldState, ok := w.tracked[path]
		if !ok {
			// not sure how this can be possible, but better safe than sorry
			continue
		}

		var (
			oldInfo  = oldState.info
			newState = state{path: oldState.path}
		)

		// os.Stat follows symlinks, os.Lstat doesn't
		info, err := os.Stat(path)
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

				// clear out old state from the map
				w.tracked[oldState.path] = newState
			}

			continue
		}

		// some other type of error encountered while doing os.Stat
		if err != nil {
			w.sendError(err)
			continue
		}

		// when encountering a directory as a tracked path, list it's contents and
		// track those, including a recursion into subdirectories.
		if info.IsDir() {
			de, err := os.ReadDir(path)
			if err != nil {
				continue
			}

			for _, f := range de {
				fp := filepath.Join(path, f.Name())
				if _, ok := w.tracked[fp]; ok {
					// this file is already being tracked, skip it
					continue
				}

				// "schedule" this file to be checked at the end the order
				order = append(order, fp)
				w.tracked[fp] = state{path: fp}
			}

			// nothing else needs to be done for directory handling
			continue
		}

		// compute the checksum of the file/symlink which is subsequently used to
		// issue Write notifications
		file, err := os.Open(path)
		if err != nil {
			w.sendError(err)
			continue
		}

		h := fnv.New64()
		_, err = io.Copy(h, file)
		_ = file.Close()
		if err != nil {
			w.sendError(err)
			continue
		}
		newState.sum64 = h.Sum64()

		if oldState.info == nil {
			// haven't seen info for this track path before -- issue a creation
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
		} else {
			// have seen this file/symlink before -- lets see if it changed size or contents
			if info.Size() != oldInfo.Size() || newState.sum64 != oldState.sum64 {
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
	if w.silent.Load() {
		return
	}

	select {
	case w.Events <- e:
		w.logger.Debug("sent fswatcher event", logfields.Event, e)
	case <-w.stop:
	}
}

func (w *Watcher) sendError(err error) {
	if w.silent.Load() {
		return
	}

	select {
	case w.Errors <- err:
	case <-w.stop:
	}
}
