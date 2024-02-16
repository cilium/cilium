// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
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
				Group: bpfEventBufferGCControllerGroup,
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
	buffer        *container.RingBuffer
	eventTTL      time.Duration
	subsLock      lock.RWMutex
	subscriptions []*Handle
}

// Handle allows for handling event streams safely outside of this package.
// The key design consideration for event streaming is that it is non-blocking.
// The eventsBuffer takes care of closing handles when their consumer is not reading
// off the buffer (or is not reading off it fast enough).
type Handle struct {
	c      chan *Event
	closed atomic.Bool
	closer *sync.Once
	err    error
}

// Returns read only channel for Handle subscription events. Channel should be closed with
// handle.Close() function.
func (h *Handle) C() <-chan *Event {
	return h.c // return read only channel to prevent closing outside of Close(...).
}

// Close allows for safaley closing of a handle.
func (h *Handle) Close() {
	h.close(nil)
}

func (h *Handle) close(err error) {
	h.closer.Do(func() {
		close(h.c)
		h.err = err
		h.closed.Store(true)
	})
}

func (h *Handle) isClosed() bool {
	return h.closed.Load()
}

func (h *Handle) isFull() bool {
	return len(h.c) >= cap(h.c)
}

// This configures how big buffers are for channels used for streaming events from
// eventsBuffer.
//
// To prevent blocking bpf.Map operations, subscribed events are buffered per client handle.
// How fast subscribers will need to proceess events will depend on the event throughput.
// In this case, our throughput will be expected to be not above 100 events a second.
// Therefore the consumer will have 10ms to process each event. The channel is also
// given a constant buffer size in the case where events arrive at once (i.e. all 100 events
// arriving at the top of the second).
//
// NOTE: Although using timers/timed-contexts seems like an obvious choice for this use case,
// the timer.After implementation actually uses a large amount of memory. To reduce memory spikes
// in high throughput cases, we instead just use a sufficiently buffered channel.
const (
	eventSubChanBufferSize = 32
	maxConcurrentEventSubs = 32
)

func (eb *eventsBuffer) hasSubCapacity() bool {
	eb.subsLock.RLock()
	defer eb.subsLock.RUnlock()
	return len(eb.subscriptions) <= maxConcurrentEventSubs
}

func (eb *eventsBuffer) dumpAndSubscribe(callback EventCallbackFunc, follow bool) (*Handle, error) {
	if follow && !eb.hasSubCapacity() {
		return nil, fmt.Errorf("exceeded max number of concurrent map event subscriptions %d", maxConcurrentEventSubs)
	}

	if callback != nil {
		eb.dumpWithCallback(callback)
	}

	if !follow {
		return nil, nil
	}

	h := &Handle{
		c:      make(chan *Event, eventSubChanBufferSize),
		closer: &sync.Once{},
	}

	eb.subsLock.Lock()
	defer eb.subsLock.Unlock()
	eb.subscriptions = append(eb.subscriptions, h)
	return h, nil
}

// DumpAndSubscribe dumps existing buffer, if callback is not nil. Followed by creating a
// subscription to the maps events buffer and returning the handle.
// These actions are done together so as to prevent possible missed events between the handoff
// of the callback and sub handle creation.
func (m *Map) DumpAndSubscribe(callback EventCallbackFunc, follow bool) (*Handle, error) {
	// note: we have to hold rlock for the duration of this to prevent missed events between dump and sub.
	// dumpAndSubscribe maintains its own write-lock for updating subscribers.
	m.lock.RLock()
	defer m.lock.RUnlock()
	if !m.eventsBufferEnabled {
		return nil, fmt.Errorf("map events not enabled for map %q", m.name)
	}
	return m.events.dumpAndSubscribe(callback, follow)
}

func (m *Map) IsEventsEnabled() bool {
	return m.eventsBufferEnabled
}

func (eb *eventsBuffer) add(e *Event) {
	eb.buffer.Add(e)
	var activeSubs []*Handle
	activeSubsLock := &lock.Mutex{}
	wg := &sync.WaitGroup{}
	for i, sub := range eb.subscriptions {
		if sub.isClosed() { // sub will be removed.
			continue
		}
		wg.Add(1)
		go func(sub *Handle, i int) {
			defer wg.Done()
			if sub.isFull() {
				err := fmt.Errorf("timed out waiting to send sub map event")
				log.WithError(err).Warnf("subscription channel buffer %d was full, closing subscription", i)
				sub.close(err)
			} else {
				sub.c <- e
				activeSubsLock.Lock()
				activeSubs = append(activeSubs, sub)
				activeSubsLock.Unlock()
			}
		}(sub, i)
	}
	wg.Wait()
	eb.subsLock.Lock()
	defer eb.subsLock.Unlock()
	eb.subscriptions = activeSubs
}

func wrongObjTypeErr(i any) error {
	return fmt.Errorf("BUG: wrong object type in event ring buffer: %T", i)
}

func (eb *eventsBuffer) eventIsValid(e interface{}) bool {
	event, ok := e.(*Event)
	if !ok {
		log.WithError(wrongObjTypeErr(e)).Error("Could not dump contents of events buffer")
		return false
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
