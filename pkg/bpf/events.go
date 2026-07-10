// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/stream"
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

var bpfEventBufferGCControllerGroup = controller.NewGroup("bpf-event-buffer-gc")

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

func newEventsBuffer(logger *slog.Logger, name string, bufSize int, ttl time.Duration) *eventsBuffer {
	b := &eventsBuffer{
		logger:   logger,
		buffer:   container.NewRingBuffer[Event](bufSize),
		eventTTL: ttl,
	}
	b.observe, b.next, b.done = stream.Multicast[Event]()
	b.observe.Observe(context.Background(), func(e Event) {
		b.buffer.Add(e)
	}, func(err error) {})
	if b.eventTTL > 0 {
		logger.Debug("starting bpf map event buffer GC controller")
		mapControllers.UpdateController(
			fmt.Sprintf("bpf-event-buffer-gc-%s", name),
			controller.ControllerParams{
				Group: bpfEventBufferGCControllerGroup,
				DoFunc: func(_ context.Context) error {
					logger.Debug(
						"clearing bpf map events older than TTL",
						logfields.TTL, b.eventTTL,
					)
					b.buffer.Compact(func(event Event) bool {
						return time.Since(event.Timestamp) < b.eventTTL
					})
					return nil
				},
				RunInterval: b.eventTTL,
			},
		)
	}
	return b
}

func (m *Map) initEventsBuffer(maxSize int, eventsTTL time.Duration) {
	m.events = newEventsBuffer(m.Logger, m.name, maxSize, eventsTTL)
}

// eventsBuffer stores a buffer of events for auditing and debugging
// purposes.
type eventsBuffer struct {
	logger   *slog.Logger
	buffer   *container.RingBuffer[Event]
	eventTTL time.Duration

	observe stream.Observable[Event]
	next    func(Event)
	done    func(error)
}

func (eb *eventsBuffer) dumpAndSubscribe(ctx context.Context, callback EventCallbackFunc, follow bool) {
	eb.dumpWithCallback(callback)
	if follow {
		eb.observe.Observe(ctx, callback, func(err error) {
			if errors.Is(err, context.Canceled) {
				eb.logger.Debug("map event observable cancelled", logfields.Error, err)
				return
			}
			eb.logger.Error("failed while observing map events", logfields.Error, err)
		})
	}
}

// DumpAndSubscribe dumps existing buffer, if callback is not nil. Followed by creating a
// subscription to the maps events buffer and returning the handle.
// These actions are done together so as to prevent possible missed events between the handoff
// of the callback and sub handle creation.
func (m *Map) DumpAndSubscribe(ctx context.Context, callback EventCallbackFunc, follow bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.events.dumpAndSubscribe(ctx, callback, follow)
}

func (m *Map) IsEventsEnabled() bool {
	return m.eventsBufferEnabled
}

func (eb *eventsBuffer) add(e *Event) {
	eb.next(*e)
}

func (eb *eventsBuffer) eventIsValid(e Event) bool {
	return eb.eventTTL == 0 || time.Since(e.Timestamp) <= eb.eventTTL
}

// EventCallbackFunc is used to dump events from a event buffer.
type EventCallbackFunc func(Event)

func (eb *eventsBuffer) dumpWithCallback(callback EventCallbackFunc) {
	eb.buffer.IterateValid(eb.eventIsValid, func(event Event) {
		callback(event)
	})
}
