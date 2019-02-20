// Copyright 2019 Authors of Cilium
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

package eventqueue

import (
	"reflect"
	"sync"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "eventqueue")
)

// EventQueue is a structure which is utilized to handle Events in a first-in,
// first-out order. An EventQueue may be closed, in which case all events which
// are queued up, but have not been processed yet, will be cancelled (i.e., not
// ran). It is guaranteed that no events will be scheduled onto an EventQueue
// after it has been closed; if any event is attempted to be scheduled onto an
// EventQueue after it has been closed, it will be cancelled immediately. For
// any event to be processed by the EventQueue, it must implement the
// `EventHandler` interface. This allows for different types of events to be
// processed by anything which chooses to utilize an `EventQueue`.
type EventQueue struct {
	// This should always be a buffered channel.
	events chan *Event
	// close is closed once the EventQueue has been closed.
	close chan struct{}
	// drained is closed once the events channel is drained.
	drained chan struct{}
	// eventQueueOnce is used to ensure that the EventQueue business logic can
	// only be ran once.
	eventQueueOnce sync.Once
}

// NewEventQueue returns an EventQueue with a capacity for only one event at
// a time, and all other needed fields initialized.
func NewEventQueue() *EventQueue {
	return &EventQueue{
		// Only one event can be consumed at a time.
		events:  make(chan *Event, 1),
		close:   make(chan struct{}),
		drained: make(chan struct{}),
	}

}

// NewEventQueueBuffered returns an EventQueue with a capacity for only one event at
// a time, and all other needed fields initialized.
func NewEventQueueBuffered(numBufferedEvents int) *EventQueue {
	return &EventQueue{
		// Up to numBufferedEvents can be Enqueued until Enqueueing blocks.
		events:  make(chan *Event, numBufferedEvents),
		close:   make(chan struct{}),
		drained: make(chan struct{}),
	}

}

// Event is an event that can be enqueued onto an EventQueue.
type Event struct {
	// Metadata is the information about the event which is sent
	// by its queuer. Metadata must implement the EventHandler interface in
	// order for the Event to be successfully processed by the EventQueue.
	Metadata EventHandler

	// EventResults is a channel on which the results of the event are sent.
	// It is populated by the EventQueue itself, not by the queuer.
	eventResults chan interface{}

	// cancelled signals that the given Event was not ran. This can happen
	// if the EventQueue processing this Event was closed before the Event was
	// Enqueued onto the Event queue, or if the Event was Enqueued onto an
	// EventQueue, and the EventQueue on which the Event was scheduled was
	// closed.
	cancelled chan struct{}

	// stats is a field which contains information about when this event is
	// enqueued, dequeued, etc.
	stats eventStatistics
}

type eventStatistics struct {

	// waitEnqueue shows how long a given event was waiting on the queue before
	// it was actually processed.
	waitEnqueue spanstat.SpanStat

	// durationStat shows how long the actual processing of the event took. This
	// is the time for how long Handle() takes for the event.
	durationStat spanstat.SpanStat

	// waitConsumeOffQueue shows how long it took for the event to be consumed
	// off of the queue.
	waitConsumeOffQueue spanstat.SpanStat
}

// NewEvent returns an Event with all fields initialized.
func NewEvent(meta EventHandler) *Event {
	return &Event{
		Metadata:     meta,
		eventResults: make(chan interface{}, 1),
		cancelled:    make(chan struct{}),
		stats:        eventStatistics{},
	}
}

// WasCancelled returns whether the cancelled channel for the given Event has
// been closed or not. Cancellation occurs if the event was not processed yet
// by an EventQueue onto which this Event was Enqueued, and the queue is closed,
// or if the event was attempted to be scheduled onto an EventQueue which has
// already been closed.
func (ev *Event) WasCancelled() bool {
	select {
	case <-ev.cancelled:
		return true
	default:
		return false
	}
}

// Enqueue pushes the given event onto the EventQueue. If the queue has been
// stopped, the Event will not be enqueued, and its cancel channel will be
// closed, indicating that the Event was not ran. This function may block if
// there is an event being processed by the queue.
func (q *EventQueue) Enqueue(ev *Event) <-chan interface{} {

	select {
	case <-q.close:
		close(ev.cancelled)
		close(ev.eventResults)
		return nil
	default:
		// The events channel may be closed even if an event has been pushed
		// onto the events channel, as events are consumed off of the events
		// channel asynchronously! If the EventQueue is closed before this
		// event is processed, then it will be cancelled.

		ev.stats.waitEnqueue.Start()
		q.events <- ev
		ev.stats.waitEnqueue.End(true)
		ev.stats.waitConsumeOffQueue.Start()
		return ev.eventResults
	}
}

func (ev *Event) printStats() {
	log.WithFields(logrus.Fields{
		"eventType":                    reflect.TypeOf(ev.Metadata).String(),
		"eventHandlingDuration":        ev.stats.durationStat.Total(),
		"eventEnqueueWaitTime":         ev.stats.waitEnqueue.Total(),
		"eventConsumeOffQueueWaitTime": ev.stats.waitConsumeOffQueue.Total(),
	}).Debug("EventQueue event processing statistics")
}

// Run consumes events that have been queued for this EventQueue. It
// is presumed that the eventQueue is a buffered channel with a length of one
// (i.e., only one event can be processed at a time). All business logic for
// handling queued events is contained within this function. If the Metadata
// within an Event does not implement the EventHandler interface, the function
// will log an error, and the Event will not be processed. If the event queue is
// closed, then all events which were queued up, but not processed, are
// cancelled. Any event which is currently being processed will not be
// cancelled. It is assumed that the caller handles both cases for an Event
// (cancel, or result of event) gracefully.
func (q *EventQueue) Run() {
	go q.eventQueueOnce.Do(func() {
		for {
			select {
			// Receive next event. No other goroutine or process should consume
			// events off of this channel!
			case ev := <-q.events:
				{
					ev.stats.waitConsumeOffQueue.End(true)
					eventHandler := ev.Metadata.(EventHandler)
					ev.stats.durationStat.Start()
					eventHandler.Handle(ev.eventResults)
					// Always indicate success for now.s
					ev.stats.durationStat.End(true)
					// Ensures that no more results can be sent as the event has
					// already been processed.
					ev.printStats()
					close(ev.eventResults)
				}
			// Cancel all events that were not yet consumed.
			case <-q.close:
				{
					// Drain queue of all events.
					for {
						select {
						case drainEvent := <-q.events:
							drainEvent.stats.waitConsumeOffQueue.End(false)
							close(drainEvent.cancelled)
							close(drainEvent.eventResults)
							drainEvent.printStats()
						default:
							// No more events are in events channel, so we can close
							// it and exit. It is guaranteed that no more events
							// will be queued onto the events channel because
							// the close channel has been closed. See Enqueue.
							close(q.drained)
							close(q.events)
							return
						}
					}
				}
			}
		}
	})
}

// Stop stops any further events from being processed by the EventQueue. Any
// event which is currently being processed by the EventQueue will continue to
// run. All other events waiting to be processed, and all events that may be
// enqueued will not be processed by the event queue; they will be cancelled.
// If the queue has already been stopped, this is a no-op.
func (q *EventQueue) Stop() {
	select {
	case <-q.close:
		log.Warning("tried to close event queue, but it already has been closed")
	default:
		log.Debug("closing event queue")
		close(q.close)
	}
}

// IsDrained returns the channel which waits for the EventQueue to be drained.
func (q *EventQueue) IsDrained() <-chan struct{} {
	return q.drained
}

// EventHandler is an interface for allowing an EventQueue to handle events
// in a generic way. To be processed by the EventQueue, all event types must
// implement any function specified in this interface.
type EventHandler interface {
	Handle(chan interface{})
}
