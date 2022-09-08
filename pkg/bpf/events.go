// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/controller"
)

// Action describes an action for map buffer events.
type Action uint8

const (
	// MapUpdate describes a map.Update event.
	MapUpdate Action = iota
	// MapDelete describes a map.Delete event.
	MapDelete
	// MapDeleteAll describes a map.DeleteAll event which is aggregated into a single event
	// to minimize memory and subscription buffer usage.
	MapDeleteAll
)

// String returns a string representation of an Action.
func (e Action) String() string {
	switch e {
	case MapUpdate:
		return "update"
	case MapDelete:
		return "delete"
	case MapDeleteAll:
		return "delete-all"
	default:
		return "unknown"
	}
}

// Event contains data about a bpf operation event.
type Event struct {
	Timestamp time.Time
	action    Action
	cacheEntry
}

// GetAction returns the event action string.
func (e *Event) GetAction() string {
	return e.action.String()
}

// GetKey returns the string representation of a event key.
func (e Event) GetKey() string {
	if e.cacheEntry.Key == nil {
		return "<nil>"
	}
	return e.cacheEntry.Key.String()
}

// GetValue returns the string representation of a event value.
// Nil values (such as with deletes) are returned as a canonical
// string representation.
func (e Event) GetValue() string {
	if e.cacheEntry.Value == nil {
		return "<nil>"
	}
	return e.cacheEntry.Value.String()
}

// GetLastError returns the last error for an event.
func (e Event) GetLastError() error {
	return e.cacheEntry.LastError
}

// GetDesiredAction returns the desired action enum for an event.
func (e Event) GetDesiredAction() DesiredAction {
	return e.cacheEntry.DesiredAction
}

func (m *Map) initEventsBuffer(maxSize int, eventsTTL time.Duration) {
	b := &eventsBuffer{
		buffer:   container.NewRingBuffer(maxSize),
		eventTTL: eventsTTL,
	}
	if b.eventTTL > 0 {
		m.scopedLogger().Debug("starting bpf map event buffer GC controller")
		mapControllers.UpdateController(
			fmt.Sprintf("bpf-event-buffer-gc-%s", m.name),
			controller.ControllerParams{
				DoFunc: func(_ context.Context) error {
					m.scopedLogger().Debugf("clearing bpf map events older than %s", b.eventTTL)
					b.buffer.Compact(func(e interface{}) bool {
						event, ok := e.(*Event)
						if !ok {
							log.WithError(wrongObjTypeErr(e)).Error("Failed to compact the event buffer")
							return false
						}
						return time.Since(event.Timestamp) < b.eventTTL
					})
					return nil
				},
				RunInterval: b.eventTTL,
			},
		)
	}
	m.events = b
}

// eventsBuffer stores a buffer of events for auditing and debugging
// purposes.
type eventsBuffer struct {
	buffer   *container.RingBuffer
	eventTTL time.Duration
}

func (eb *eventsBuffer) add(e *Event) {
	eb.buffer.Add(e)
}

func wrongObjTypeErr(i any) error {
	return fmt.Errorf("BUG: wrong object type in event ring buffer: %T", i)
}

func (eb *eventsBuffer) eventIsValid(e interface{}) bool {
	event, ok := e.(*Event)
	if !ok {
		log.WithError(wrongObjTypeErr(e)).Error("Could not dump contents of events buffer")
		return true
	}
	return eb.eventTTL == 0 || time.Since(event.Timestamp) <= eb.eventTTL
}

// EventCallbackFunc is used to dump events from a event buffer.
type EventCallbackFunc func(*Event)

func (eb *eventsBuffer) dumpWithCallback(callback EventCallbackFunc) {
	eb.buffer.IterateValid(eb.eventIsValid, func(e interface{}) {
		event, ok := e.(*Event)
		if !ok {
			log.WithError(wrongObjTypeErr(e)).Error("Could not dump contents of events buffer")
			return
		}
		callback(event)
	})
}

// DumpEventWithCallback applies the callback function to all events in the buffer,
// in order, from oldest to newest.
func (m *Map) DumpEventsWithCallback(callback EventCallbackFunc) error {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if !m.eventsBufferEnabled || m.events == nil {
		return fmt.Errorf("events buffer not enabled for map %q", m.name)
	}
	m.events.dumpWithCallback(callback)
	return nil
}
