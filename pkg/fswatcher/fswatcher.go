// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fswatcher")

// Event currently wraps fsnotify.Event
type Event fsnotify.Event

// Watcher is a wrapper around fsnotify.Watcher which can track non-existing
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
	watcher *fsnotify.Watcher

	// Internally, we distinguish between
	watchedPathCount     counter.StringCounter
	trackedToWatchedPath map[string]string

	// Events is used to signal changes to any of the tracked files. It is
	// guaranteed that Event.Name will always match one of the file paths
	// passed in trackedFiles to the constructor. This channel is unbuffered
	// and must be read by the consumer to avoid deadlocks.
	Events chan Event
	// Errors reports any errors which may occur while watching. This channel
	// is unbuffered and must be read by the consumer to avoid deadlocks.
	Errors chan error

	// stop channel used to indicate shutdown
	stop chan struct{}
}

// New creates a new Watcher which watches all trackedFile paths (they do not
// need to exist yet).
func New(trackedFiles []string) (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		watcher:              watcher,
		watchedPathCount:     counter.StringCounter{},
		trackedToWatchedPath: map[string]string{},
		Events:               make(chan Event),
		Errors:               make(chan error),
		stop:                 make(chan struct{}),
	}

	// We add all paths in the constructor avoid the need for additional
	// synchronization, as the loop goroutine below will call updateWatchedPath
	// concurrently
	for _, f := range trackedFiles {
		err := w.updateWatchedPath(f)
		if err != nil {
			return nil, err
		}
	}

	go w.loop()

	return w, nil
}

func (w *Watcher) Close() {
	close(w.stop)
}

func (w *Watcher) updateWatchedPath(trackedPath string) error {
	trackedPath = filepath.Clean(trackedPath)

	// Remove old watchedPath
	oldWatchedPath, ok := w.trackedToWatchedPath[trackedPath]
	if ok {
		w.stopWatching(oldWatchedPath)
	}

	// Finds and watches the new watchedPath
	watchedPath, err := w.startWatching(trackedPath)
	if err != nil {
		return fmt.Errorf("failed to add fsnotify watcher for %q (parent of %q): %w",
			watchedPath, trackedPath, err)
	}

	// Update the mapping
	w.trackedToWatchedPath[trackedPath] = watchedPath
	return nil
}

func (w *Watcher) startWatching(path string) (string, error) {
	// If the path is already watched, we do not want to add it to fsnotify
	// again, thus the check on the refcount first.
	// Note: If we already watchedPath has been invalidated recently,
	// this if statement will be false (because invalidateWatch resets the
	// count)
	if w.watchedPathCount[path] > 0 {
		w.watchedPathCount.Add(path)
		return path, nil
	}

	// Adds the file to fsnotify. Important note: If path is a symlink, this
	// will watch the *target* of the symlink. So any event we will observe,
	// will be valid for the target, not for the symlink itself. The reported
	// path in the events however will remain the path of the symlink.
	err := w.watcher.Add(path)
	if err != nil {
		// if the path does not exist, try to watch its parent instead
		if errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(path)
			if parent != path {
				return w.startWatching(parent)
			}
		}

		return "", err
	}

	// Start counting the references for the watched path.
	// The following is identical to `w.watchedPathCount[path] = 1`, because
	// w.watchedPathCount[path] was zero when we entered the function
	w.watchedPathCount.Add(path)
	return path, nil
}

func (w *Watcher) stopWatching(path string) {
	// Decrease the refcount for the old watchedPath. If this was the last
	// use of this watchedPath, we remove it from the underlying fsnotify
	// watcher.
	if w.watchedPathCount.Delete(path) {
		_ = w.watcher.Remove(path)
	}
}

func (w *Watcher) invalidateWatch(path string) {
	if w.watchedPathCount[path] > 0 {
		delete(w.watchedPathCount, path)
		// The result is ignored because fsnotify removes deleted paths by
		// itself, in which case it will complain about a non-existing path
		// being removed.
		_ = w.watcher.Remove(path)
	}
}

// hasParent returns true if path is a child or equal to parent
func hasParent(path, parent string) bool {
	path = filepath.Clean(path)
	parent = filepath.Clean(parent)
	if path == parent {
		return true
	}

	for {
		pathParent := filepath.Dir(path)
		if pathParent == parent {
			return true
		}

		// reached the root
		if pathParent == path {
			return false
		}

		path = pathParent
	}
}

// loop filters and processes fsnoity events. It may generate artificial
// `Create` events in case observes that files which did not exist before now
// exist. This exits after w.Close() is called
func (w *Watcher) loop() {
	for {
		select {
		case event := <-w.watcher.Events:
			scopedLog := log.WithFields(logrus.Fields{
				logfields.Path: event.Name,
				"operation":    event.Op,
			})
			scopedLog.Debug("Received fsnotify event")

			eventPath := event.Name
			removed := event.Has(fsnotify.Remove)
			renamed := event.Has(fsnotify.Rename)
			created := event.Has(fsnotify.Create)
			written := event.Has(fsnotify.Write)

			// If a the eventPath has been removed or renamed, it can no longer
			// be a valid watchPath. This is needed such that each trackedPath
			// is updated with a new valid watchPath in the call
			// to updateWatchedPath below.
			eventPathInvalidated := removed || renamed
			if eventPathInvalidated {
				w.invalidateWatch(eventPath)
			}

			// We iterate over all tracked files here, checking either if
			// the event affects the trackedPath (in which case we want to
			// forward it) and to check if the event affects the watchedPath,
			// in which case we likely need to update the watchedPath
			for trackedPath, watchedPath := range w.trackedToWatchedPath {
				// If the event happened on a tracked path, we can forward
				// it in all cases
				if eventPath == trackedPath {
					w.Events <- Event{
						Name: trackedPath,
						Op:   event.Op,
					}
				}

				// If the event path has been invalidated (i.e. removed or
				// renamed), we need to update the watchedPath for this file
				if eventPathInvalidated && eventPath == watchedPath {
					// In this case, the watchedPath has been invalidated. There
					// are multiple cases which are handled by the call to
					// updateWatchedPath below:
					// - watchedPath == trackedPath:
					//   - trackedPath is a regular file:
					//      In this case, the tracked file has been deleted or
					//      moved away. This means updateWatchedPath will start
					//      watching a parent folder of trackedPath to pick up
					//      the creation event.
					//  - trackedPath is a symlink:
					//      This means the target of the symlink has been deleted.
					//      If the symlink already points to a new valid target
					//      (this e.g. happens in Kubernetes volume mounts. In,
					//      that case the new target of the symlink will be the
					//      new watchedPath.
					// - watchedPath was a parent of trackedPath
					//    In this case we will start watching a parent of
					//     the old watchedPath.
					err := w.updateWatchedPath(trackedPath)
					if err != nil {
						w.Errors <- err
					}

					// If trackedPath is a symlink, it can happen that the old
					// symlink target was deleted, but symlink itself has been
					// redirected to a new target. We can detect this, if
					// after the call to `updateWatchedPath` above, the
					// tracked and watched path are identical. In such a
					// case, we emit a create event for the symlink.
					newWatchedPath := w.trackedToWatchedPath[trackedPath]
					if newWatchedPath == trackedPath {
						w.Events <- Event{
							Name: trackedPath,
							Op:   fsnotify.Create,
						}
					}
				}

				if created || written {
					// If a new eventPath been created or written to, we need
					// to check if the new eventPath should be watched. There
					// are two conditions (both have to be true):
					// - eventPath is a parent of trackedPath. If it is not,
					//   then it is unrelated to the file we are trying to track.
					parentOfTrackedPath := hasParent(trackedPath, eventPath)
					// - eventPath is a child of the current watchedPath. In
					//   other words, eventPath is a better candidate to watch
					//   than our current watchedPath.
					childOfWatchedPath := hasParent(eventPath, watchedPath)
					// Example:
					// 	watchedPath:  /tmp           (we are watching this)
					// 	eventPath:    /tmp/foo       (this was just created, it should become the new watchedPath)
					// 	trackedPath:  /tmp/foo/bar   (we want emit an event if is created)
					if childOfWatchedPath && parentOfTrackedPath {
						// The event happened on a child of the watchedPath
						// and a parent of the trackedPath. This means that
						// we have found a better watched path.
						err := w.updateWatchedPath(trackedPath)
						if err != nil {
							w.Errors <- err
						}

						// This checks if the new watchedPath after the call
						// to `updateWatchedPath` is now equal to the trackedPath.
						// This implies that the creation of a parent of the
						// trackedPath has also led to the trackedPath itself
						// existing now. This can happen e.g. if the parent was
						// a symlink.
						newWatchedPath := w.trackedToWatchedPath[trackedPath]
						if newWatchedPath == trackedPath {
							// The check for `eventPath != trackedPath` is to
							// avoid a duplicate creation event (because at the
							// top of the loop body, we forward any event on
							// the  trackedPath unconditionally)
							if eventPath != trackedPath {
								w.Events <- Event{
									Name: trackedPath,
									Op:   fsnotify.Create,
								}
							}
						}
					}
				}
			}
		case err := <-w.watcher.Errors:
			log.WithError(err).Debug("Received fsnotify error while watching")
			w.Errors <- err
		case <-w.stop:
			err := w.watcher.Close()
			if err != nil {
				log.WithError(err).Warn("Received fsnotify error on close")
			}
			close(w.Events)
			close(w.Errors)
			return
		}
	}
}
