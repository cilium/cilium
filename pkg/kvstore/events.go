// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package kvstore

import (
	"context"
	"sync"
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

	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	stopWatch stopChan

	// stopOnce guarantees that Stop() is only called once
	stopOnce sync.Once

	// stopWait is the wait group to wait for watchers to exit gracefully
	stopWait sync.WaitGroup
}

func newWatcher(name, prefix string, chanSize int) *Watcher {
	w := &Watcher{
		Name:      name,
		Prefix:    prefix,
		Events:    make(EventChan, chanSize),
		stopWatch: make(stopChan),
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
		log.WithField(fieldWatcher, w).Debug("Stopped watcher")
		w.stopWait.Wait()
	})
}
