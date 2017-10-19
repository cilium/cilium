// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kvstore

import (
	"sync"

	log "github.com/sirupsen/logrus"
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
	default:
		return "unknown"
	}
}

// KeyValueEvent is a change event for a Key/Value pair
type KeyValueEvent struct {
	// Typ is the type of event { EventTypeCreate | EventTypeModify | EventTypeDelete }
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
	Events EventChan

	name      string
	prefix    string
	stopWatch stopChan

	stopped bool

	// stopWait is used to wait for the watcher subroutine to quit
	stopWait sync.WaitGroup
}

// String returns the name of the wather
func (w *Watcher) String() string {
	return w.name
}

func watch(name, prefix string, chanSize int, list bool) *Watcher {
	w := &Watcher{
		name:      name,
		prefix:    prefix,
		Events:    make(EventChan, chanSize),
		stopWatch: make(stopChan, 0),
	}

	log.WithFields(log.Fields{
		fieldWatcher:      w,
		fieldListAndWatch: list,
	}).Debug("Starting watcher...")

	go func() {
		// Signal termination of watcher routine
		defer w.stopWait.Done()
		Client().Watch(w, list)
	}()

	return w
}

// Watch creates a new watcher which will watch the specified prefix for
// changes. Name can be set to anything and is used for logging messages. The
// Events channel is created with the specified sizes. Upon every change
// observed, a KeyValueEvent will be sent to the Events channel
func Watch(name, prefix string, chanSize int) *Watcher {
	return watch(name, prefix, chanSize, false)

}

// ListAndWatch creates a new watcher which will watch the specified prefix for
// changes. Before doing this, it will list the current keys matching the
// prefix and report them as new keys. Name can be set to anything and is used
// for logging messages. The Events channel is created with the specified
// sizes. Upon every change observed, a KeyValueEvent will be sent to the
// Events channel
func ListAndWatch(name, prefix string, chanSize int) *Watcher {
	return watch(name, prefix, chanSize, true)
}

// Stop stops a watcher previously created and started with Watch()
func (w *Watcher) Stop() {
	if w.stopped {
		return
	}

	// Stop watcher go routine and wait for it to terminate before closing
	// the events channel
	w.stopWait.Add(1)
	close(w.stopWatch)
	w.stopWait.Wait()

	close(w.Events)

	log.WithField(fieldWatcher, w).Debug("Stopped watcher...")

	w.stopped = true
}
