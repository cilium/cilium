// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package kvstore

import (
	"context"
	"sync"

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

	Prefix    string `json:"prefix"`
	stopWatch stopChan

	// stopOnce guarantees that Stop() is only called once
	stopOnce sync.Once

	// stopWait is the wait group to wait for watchers to exit gracefully
	stopWait sync.WaitGroup
}

func newWatcher(prefix string, chanSize int) *Watcher {
	w := &Watcher{
		Prefix:    prefix,
		Events:    make(EventChan, chanSize),
		stopWatch: make(stopChan),
	}

	w.stopWait.Add(1)

	return w
}

// emit attempts to notify the watcher of an event within the given context.
// returning false if the context is done before the event is emitted.
func (w *Watcher) emit(ctx context.Context, scope string, event KeyValueEvent) bool {
	queueStart := spanstat.Start()
	var ok bool
	select {
	case <-ctx.Done():
	case <-w.stopWatch:
	case w.Events <- event:
		ok = true
	}
	trackEventQueued(scope, event.Typ, queueStart.End(ok).Total())
	return ok
}

// Stop stops a watcher previously created and started with Watch()
func (w *Watcher) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopWatch)
		log.WithField(fieldPrefix, w.Prefix).Debug("Stopped watcher")
		w.stopWait.Wait()
	})
}
