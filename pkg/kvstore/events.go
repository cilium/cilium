// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package kvstore

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/spanstat"
)

// EventType defines the type of watch event that occurred
type EventType int

const (
	// EventTypeCreate represents a newly created key
	EventTypeCreate EventType = iota
	// EventTypeModify represents a modified key
	EventTypeModify
	// EventTypeDelete represents a deleted key
	EventTypeDelete
	//EventTypeListDone signals that the initial list operation has completed
	EventTypeListDone
	// EventTypeDrainDone signals that the RestartableWatcher has been drained completely
	EventTypeDrainDone
)

// String() returns the human readable format of an event type
func (t EventType) String() string {
	switch t {
	case EventTypeCreate:
		return "create"
	case EventTypeModify:
		return "modify"
	case EventTypeDelete:
		return "delete"
	case EventTypeListDone:
		return "listDone"
	case EventTypeDrainDone:
		return "drainDone"
	default:
		return "unknown"
	}
}

// KeyValueEvent is a change event for a Key/Value pair
type KeyValueEvent struct {
	// Typ is the type of event { EventTypeCreate | EventTypeModify | EventTypeDelete | EventTypeListDone }
	Typ EventType

	// Key is the kvstore key that changed
	Key string

	// Value is the kvstore value associated with the key
	Value []byte
}

// EventChan is a channel to receive events on
type EventChan chan KeyValueEvent

// stopChan is the channel used to indicate stopping of the watcher
type stopChan chan struct{}

// Watcher represents a KVstore watcher
type Watcher struct {
	// Events is the channel to which change notifications will be sent to
	Events EventChan `json:"-"`

	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	stopWatch stopChan

	log *logrus.Entry

	// stopOnce guarantees that Stop() is only called once
	stopOnce sync.Once

	// stopWait is the wait group to wait for watchers to exit gracefully
	stopWait sync.WaitGroup
}

func newWatcher(name, prefix string, chanSize int, log *logrus.Entry) *Watcher {
	w := &Watcher{
		Name:      name,
		Prefix:    prefix,
		Events:    make(EventChan, chanSize),
		stopWatch: make(stopChan),

		log: log.WithFields(logrus.Fields{
			fieldWatcher: name,
			fieldPrefix:  prefix,
		}),
	}

	w.stopWait.Add(1)

	return w
}

// String returns the name of the wather
func (w *Watcher) String() string {
	return w.Name
}

// ListAndWatch creates a new watcher which will watch the specified prefix for
// changes. Before doing this, it will list the current keys matching the
// prefix and report them as new keys. Name can be set to anything and is used
// for logging messages. The Events channel is created with the specified
// sizes. Upon every change observed, a KeyValueEvent will be sent to the
// Events channel
//
// Returns a watcher structure plus a channel that is closed when the initial
// list operation has been completed
func ListAndWatch(ctx context.Context, name, prefix string, chanSize int) *Watcher {
	return Client().ListAndWatch(ctx, name, prefix, chanSize)
}

// Stop stops a watcher previously created and started with Watch()
func (w *Watcher) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopWatch)
		w.log.Debug("Stopped watcher")
		w.stopWait.Wait()
	})
}

// RestartableWatcher implements a wrapper around a KVstore watcher, automatically
// handling the generation of deletion events for stale keys during reconnections.
type RestartableWatcher struct {
	Events EventChan

	watcher   *Watcher
	knownKeys watcherCache
	log       *logrus.Entry

	mu lock.Mutex
	wg sync.WaitGroup
}

// NewRestartableWatcher creates a new RestartableWatcher with the given parameters.
func NewRestartableWatcher(chanSize int) *RestartableWatcher {
	return &RestartableWatcher{
		Events:    make(EventChan, chanSize),
		knownKeys: watcherCache{},
		log:       log.WithField(fieldWatcher, "unset"),
	}
}

// Wrap takes ownership of the given Watcher, and starts keeping track and forwarding
// all events. Once the initial list operation is completed, deletion events are
// triggered for all stale entries.
func (rw *RestartableWatcher) Wrap(watcher *Watcher) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.stopWatcherLocked()

	// Mark all previously known keys as stale. We will trigger a deletion event for
	// the ones that will not be refreshed during the initial list process.
	rw.knownKeys.MarkAllForDeletion()

	rw.watcher = watcher
	rw.log = rw.watcher.log
	rw.log.Debug("Watcher wrapped")

	// Start the loop which takes care of keeping the cache up-to-date and forwarding
	// all events. When ListDone is received, it triggers the generation of a deletion
	// event for all stale keys.
	rw.wg.Add(1)
	go rw.loop()
}

// Stop stops the watcher. The Events channel is not closed, and Wrap can be called again.
func (rw *RestartableWatcher) Stop() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.stopWatcherLocked()
}

// StopAndDrain stops the watcher and emits a deletion event for all known keys; finally,
// the DrainDone event is emitted to signal the completion of the operation. The Events
// channel is not closed, and Wrap can be called again.
func (rw *RestartableWatcher) StopAndDrain() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.drainLocked()
	rw.log.Debugf("Drain operation completed: emitting %s event", EventTypeDrainDone)
	rw.Events <- KeyValueEvent{Typ: EventTypeDrainDone}
}

// Close stops the watcher and closes the Events channel. At this point, the
// RestartableWatcher cannot be reused.
func (rw *RestartableWatcher) Close() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.stopWatcherLocked()
	close(rw.Events)
}

// CloseAndDrain stops the watcher, emits a deletion event for all known keys and then
// closes the Events channel. At this point, the RestartableWatcher cannot be reused.
func (rw *RestartableWatcher) CloseAndDrain() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.drainLocked()
	close(rw.Events)
}

func (rw *RestartableWatcher) loop() {
	for {
		select {
		case ev, ok := <-rw.watcher.Events:
			// The events channel gets closed when the watcher is stopped.
			if !ok {
				rw.wg.Done()
				return
			}

			switch ev.Typ {
			case EventTypeListDone:
				rw.emitDeletionEventForStaleEntries()

			case EventTypeCreate, EventTypeModify:
				if rw.knownKeys.Exists(ev.Key) && ev.Typ == EventTypeCreate {
					rw.log.Debugf("Converting event from %s to %s for %s, as already seen",
						EventTypeCreate, EventTypeModify, ev.Key)
					ev.Typ = EventTypeModify
				}

				rw.knownKeys.MarkInUse(ev.Key)
			case EventTypeDelete:
				rw.knownKeys.RemoveKey(ev.Key)
			}

			rw.Events <- ev
		}
	}
}

func (rw *RestartableWatcher) emitDeletionEventForStaleEntries() {
	rw.knownKeys.RemoveDeleted(func(key string) {
		rw.log.Debugf("Emitting %s event for stale key %s", EventTypeDelete, key)
		queueStart := spanstat.Start()
		rw.Events <- KeyValueEvent{
			Typ: EventTypeDelete,
			Key: key,
		}
		trackEventQueued(key, EventTypeDelete, queueStart.End(true).Total())
	})
}

// stopWatcherLocked stops the watcher, and waits for the loop goroutine to terminate.
// It must be called while holding rw.mu.
func (rw *RestartableWatcher) stopWatcherLocked() {
	if rw.watcher != nil {
		rw.watcher.Stop()
		rw.wg.Wait()
		rw.log.Debug("Watcher unwrapped")
		rw.watcher = nil
	}
}

// drainLocked stops the watcher and emits a deletion event for all known keys.
// It must be called while holding rw.mu.
func (rw *RestartableWatcher) drainLocked() {
	rw.stopWatcherLocked()

	rw.log.Debug("Draining all known keys")
	rw.knownKeys.MarkAllForDeletion()
	rw.emitDeletionEventForStaleEntries()
}
