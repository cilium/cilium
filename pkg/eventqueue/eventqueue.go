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
	"sync"
)

// EventQueue is a structured which is utilized to handle events for a given
// Endpoint in a generic way.
type EventQueue struct {
	// This should always be a buffered channel.
	events         chan *Event
	close          chan struct{}
	drained        chan struct{}
	eventQueueOnce sync.Once
}

func NewEventQueue() *EventQueue {
	return &EventQueue{
		// Only one event can be consumed per endpoint
		// at a time.
		events:  make(chan *Event, 1),
		close:   make(chan struct{}),
		drained: make(chan struct{}),
	}

}

// Event is an event that can be queued for an Endpoint on its
// EventQueue.
type Event struct {
	// Metadata is the information about the event which is sent
	// by its queuer.
	Metadata interface{}

	// EventResults is a channel on which the results of the event are sent.
	// It is populated by the EventQueue itself, not by the queuer.
	EventResults chan interface{}

	// Cancelled is a channel which is closed when the EventQueue is being
	// drained. It signals that the given Event was not ran.
	Cancelled chan struct{}
}

// NewEvent returns an Event with all fields initialized.
func NewEvent(meta interface{}) *Event {
	return &Event{
		Metadata:     meta,
		EventResults: make(chan interface{}, 1),
		Cancelled:    make(chan struct{}),
	}
}

// WasCancelled returns whether the Cancelled channel for the given even has
// been closed or not.
func (q *Event) WasCancelled() bool {
	select {
	case <-q.Cancelled:
		return true
	default:
		return false
	}
}

// Enqueue pushes the given event onto the EventQueue. If the queue has been
// stopped, the Event will not be enqueued, and its cancel channel will be
// closed, indicating that the Event was not ran. This function may block if
// there is an event being processed by the queue.
func (q *EventQueue) Enqueue(ev *Event) {
	select {
	case <-q.close:
		close(ev.Cancelled)
	default:
		// The events channel will not be closed, because it is only closed if
		// the close channel is closed for an EventQueue.
		q.events <- ev
	}
}

// Run consumes events that have been queued for this EventQueue. It
// is presumed that the eventQueue is a buffered channel with a length of one
// (i.e., only one event can be processed at a time).
// All business logic for handling queued events is contained within this
// function. Each event must be handled in such a way such that a result is sent
// across  its EventResults channel, as the queuer of an event may be waiting on
// a result from the event. Otherwise, if the event queue is closed, then all
// events which were queued up are cancelled. It is assumed that the caller
// handles both cases (cancel, or result) gracefully.
func (q *EventQueue) Run() {
	q.eventQueueOnce.Do(func() {
		for {
			select {
			// Receive next event. No other goroutine or process should consume
			// events off of this channel!
			case e := <-q.events:
				{
					// Handle each event type.
					switch t := e.Metadata.(type) {
					case EventHandler:
						ev := e.Metadata.(EventHandler)
						evRes := ev.Handle()
						e.EventResults <- evRes
					default:
						log.Errorf("unsupported function type provided to event queue: %T", t)
					}

					// Ensures that no more results can be sent as the event has
					// already been processed.
					close(e.EventResults)
				}
			// Cancel all events that were not yet consumed.
			case <-q.close:
				{
					// Drain queue of all events.
					for {
						select {
						case drainEvent := <-q.events:
							close(drainEvent.Cancelled)
							// TODO close results channel here??
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

// EventHandler is an interface for allowing an EventQueue to handle events
// in a generic way. To be processed by the EventQueue, all event types must
// implement any function specified in this interface.
type EventHandler interface {
	Handle() interface{}
}
