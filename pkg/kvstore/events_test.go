// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRestartableWatcherSuite(t *testing.T) {
	rw := NewRestartableWatcher(10)

	newWatcher := func() *Watcher {
		watcher := Watcher{Events: make(EventChan, 10), stopWatch: make(stopChan), log: log}
		go func() {
			// This is required since we are not actually starting the watcher,
			// which would take care of closing the Events channel when stopped.
			<-watcher.stopWatch
			close(watcher.Events)
		}()
		return &watcher
	}

	// Stopping and draining an uninitialized restastable watcher should emit the DrainDone event only.
	rw.StopAndDrain()
	require.Equal(t, KeyValueEvent{Typ: EventTypeDrainDone}, <-rw.Events)

	watcher1 := newWatcher()
	rw.Wrap(watcher1)

	watcher1.Events <- KeyValueEvent{Typ: EventTypeCreate, Key: "foo"}
	watcher1.Events <- KeyValueEvent{Typ: EventTypeCreate, Key: "bar"}
	watcher1.Events <- KeyValueEvent{Typ: EventTypeCreate, Key: "baz"}
	watcher1.Events <- KeyValueEvent{Typ: EventTypeListDone}
	watcher1.Events <- KeyValueEvent{Typ: EventTypeModify, Key: "bar"}
	watcher1.Events <- KeyValueEvent{Typ: EventTypeDelete, Key: "foo"}

	// Assert that all events are properly propagated
	require.Equal(t, KeyValueEvent{Typ: EventTypeCreate, Key: "foo"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeCreate, Key: "bar"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeCreate, Key: "baz"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeListDone}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeModify, Key: "bar"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeDelete, Key: "foo"}, <-rw.Events)

	watcher2 := newWatcher()
	rw.Wrap(watcher2)

	watcher2.Events <- KeyValueEvent{Typ: EventTypeCreate, Key: "bar"}
	watcher2.Events <- KeyValueEvent{Typ: EventTypeCreate, Key: "qux"}
	watcher2.Events <- KeyValueEvent{Typ: EventTypeListDone}
	watcher2.Events <- KeyValueEvent{Typ: EventTypeCreate, Key: "baz"}

	// The "bar" key was already known, hence the event is converted to Modify.
	require.Equal(t, KeyValueEvent{Typ: EventTypeModify, Key: "bar"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeCreate, Key: "qux"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeDelete, Key: "baz"}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeListDone}, <-rw.Events)
	require.Equal(t, KeyValueEvent{Typ: EventTypeCreate, Key: "baz"}, <-rw.Events)

	// Drain all remaining events. Given that they are spilled out from a map
	// there is no ordering guarantee; hence, let's sort them before checking.
	rw.CloseAndDrain()

	var events []KeyValueEvent
	events = append(events, <-rw.Events)
	events = append(events, <-rw.Events)
	events = append(events, <-rw.Events)
	sort.Slice(events, func(i, j int) bool { return events[i].Key < events[j].Key })

	require.Equal(t, KeyValueEvent{Typ: EventTypeDelete, Key: "bar"}, events[0])
	require.Equal(t, KeyValueEvent{Typ: EventTypeDelete, Key: "baz"}, events[1])
	require.Equal(t, KeyValueEvent{Typ: EventTypeDelete, Key: "qux"}, events[2])

	select {
	case _, ok := <-rw.Events:
		require.False(t, ok, "The Events channel should have been closed")
	default:
		require.Fail(t, "The Events channel should have been closed")
	}
}
