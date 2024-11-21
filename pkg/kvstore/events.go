// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package kvstore

import (
	"context"

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
type EventChan <-chan KeyValueEvent

// emitter wraps the channel to send events to, to ensure it is accessed
// via the proper helper methods.
type emitter struct {
	events chan<- KeyValueEvent
	scope  string
}

// emit attempts to notify the watcher of an event within the given context.
// returning false if the context is done before the event is emitted.
func (e emitter) emit(ctx context.Context, event KeyValueEvent) bool {
	queueStart := spanstat.Start()
	var ok bool
	select {
	case <-ctx.Done():
	case e.events <- event:
		ok = true
	}
	trackEventQueued(e.scope, event.Typ, queueStart.End(ok).Total())
	return ok
}

// close closes the events channel.
func (e emitter) close() {
	close(e.events)
}
