// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventqueue

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"
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
	// events represents the queue of events. This should always be a buffered
	// channel.
	events chan *Event

	// close is closed once the EventQueue has been closed.
	close chan struct{}

	// drain is closed when the EventQueue is stopped. Any Event which is
	// Enqueued after this channel is closed will be cancelled / not processed
	// by the queue. If an Event has been Enqueued, but has not been processed
	// before this channel is closed, it will be cancelled and not processed
	// as well.
	drain chan struct{}

	// eventQueueOnce is used to ensure that the EventQueue business logic can
	// only be ran once.
	eventQueueOnce sync.Once

	// closeOnce is used to ensure that the EventQueue can only be closed once.
	closeOnce sync.Once

	// name is used to differentiate this EventQueue from other EventQueues that
	// are also running in logs
	name string

	eventsMu lock.RWMutex

	// eventsClosed is a channel that's closed when the event loop (Run())
	// terminates.
	eventsClosed chan struct{}
}

// NewEventQueue returns an EventQueue with a capacity for only one event at
// a time.
func NewEventQueue() *EventQueue {
	return NewEventQueueBuffered("", 1)
}

// NewEventQueueBuffered returns an EventQueue with a capacity of,
// numBufferedEvents at a time, and all other needed fields initialized.
func NewEventQueueBuffered(name string, numBufferedEvents int) *EventQueue {
	log.WithFields(logrus.Fields{
		"name":              name,
		"numBufferedEvents": numBufferedEvents,
	}).Debug("creating new EventQueue")
	return &EventQueue{
		name: name,
		// Up to numBufferedEvents can be Enqueued until Enqueueing blocks.
		events:       make(chan *Event, numBufferedEvents),
		close:        make(chan struct{}),
		drain:        make(chan struct{}),
		eventsClosed: make(chan struct{}),
	}
}

// Enqueue pushes the given event onto the EventQueue. If the queue has been
// stopped, the Event will not be enqueued, and its cancel channel will be
// closed, indicating that the Event was not ran. This function may block if
// the queue is at its capacity for events. If a single Event has Enqueue
// called on it multiple times asynchronously, there is no guarantee as to
// which one will return the channel which passes results back to the caller.
// It is up to the caller to check whether the returned channel is nil, as
// waiting to receive on such a channel will block forever. Returns an error
// if the Event has been previously enqueued, if the Event is nil, or the queue
// itself is not initialized properly.
func (q *EventQueue) Enqueue(ev *Event) (<-chan interface{}, error) {
	if q.notSafeToAccess() || ev == nil {
		return nil, fmt.Errorf("unable to Enqueue event")
	}

	// Events can only be enqueued once.
	if !ev.enqueued.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("unable to Enqueue event; event has already had Enqueue called on it")
	}

	// Multiple Enqueues can occur at the same time. Ensure that events channel
	// is not closed while we are enqueueing events.
	q.eventsMu.RLock()
	defer q.eventsMu.RUnlock()

	select {
	// The event should be drained from the queue (e.g., it should not be
	// processed).
	case <-q.drain:
		// Closed eventResults channel signifies cancellation.
		close(ev.cancelled)
		close(ev.eventResults)

		return ev.eventResults, nil
	default:
		// The events channel may be closed even if an event has been pushed
		// onto the events channel, as events are consumed off of the events
		// channel asynchronously! If the EventQueue is closed before this
		// event is processed, then it will be cancelled.

		ev.stats.waitEnqueue.Start()
		ev.stats.waitConsumeOffQueue.Start()
		q.events <- ev
		ev.stats.waitEnqueue.End(true)
		return ev.eventResults, nil
	}
}

// Event is an event that can be enqueued onto an EventQueue.
type Event struct {
	// Metadata is the information about the event which is sent
	// by its queuer. Metadata must implement the EventHandler interface in
	// order for the Event to be successfully processed by the EventQueue.
	Metadata EventHandler

	// eventResults is a channel on which the results of the event are sent.
	// It is populated by the EventQueue itself, not by the queuer. This channel
	// is closed if the event is cancelled.
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

	// enqueued specifies whether this event has been enqueued on an EventQueue.
	enqueued atomic.Bool
}

type eventStatistics struct {

	// waitEnqueue shows how long a given event was waiting on the queue before
	// it was actually processed.
	waitEnqueue spanstat.SpanStat

	// durationStat shows how long the actual processing of the event took. This
	// is the time for how long Handle() takes for the event.
	durationStat spanstat.SpanStat

	// waitConsumeOffQueue shows how long it took for the event to be consumed
	// plus the time it the event waited in the queue.
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

func (ev *Event) printStats(q *EventQueue) {
	if option.Config.Debug {
		q.getLogger().WithFields(logrus.Fields{
			"eventType":                    reflect.TypeOf(ev.Metadata).String(),
			"eventHandlingDuration":        ev.stats.durationStat.Total(),
			"eventEnqueueWaitTime":         ev.stats.waitEnqueue.Total(),
			"eventConsumeOffQueueWaitTime": ev.stats.waitConsumeOffQueue.Total(),
		}).Debug("EventQueue event processing statistics")
	}
}

// Run consumes events that have been queued for this EventQueue. It
// is presumed that the eventQueue is a buffered channel with a length of one
// (i.e., only one event can be processed at a time). All business logic for
// handling queued events is contained within this function. The events in the
// queue must implement the EventHandler interface. If the event queue is
// closed, then all events which were queued up, but not processed, are
// cancelled; any event which is currently being processed will not be
// cancelled.
func (q *EventQueue) Run() {
	if q.notSafeToAccess() {
		return
	}

	go q.run()
}

func (q *EventQueue) run() {
	q.eventQueueOnce.Do(func() {
		defer close(q.eventsClosed)
		for ev := range q.events {
			select {
			case <-q.drain:
				ev.stats.waitConsumeOffQueue.End(false)
				close(ev.cancelled)
				close(ev.eventResults)
				ev.printStats(q)
			default:
				ev.stats.waitConsumeOffQueue.End(true)
				ev.stats.durationStat.Start()
				ev.Metadata.Handle(ev.eventResults)
				// Always indicate success for now.
				ev.stats.durationStat.End(true)
				// Ensures that no more results can be sent as the event has
				// already been processed.
				ev.printStats(q)
				close(ev.eventResults)
			}
		}
	})
}

func (q *EventQueue) notSafeToAccess() bool {
	return q == nil || q.close == nil || q.drain == nil || q.events == nil
}

// Stop stops any further events from being processed by the EventQueue. Any
// event which is currently being processed by the EventQueue will continue to
// run. All other events waiting to be processed, and all events that may be
// enqueued will not be processed by the event queue; they will be cancelled.
// If the queue has already been stopped, this is a no-op.
func (q *EventQueue) Stop() {
	if q.notSafeToAccess() {
		return
	}

	q.closeOnce.Do(func() {
		q.getLogger().Debug("stopping EventQueue")
		// Any event that is sent to the queue at this point will be cancelled
		// immediately in Enqueue().
		close(q.drain)

		// Signal that the queue has been drained.
		close(q.close)

		q.eventsMu.Lock()
		close(q.events)
		q.eventsMu.Unlock()
	})
}

// WaitToBeDrained returns the channel which waits for the EventQueue to have been
// stopped. This allows for queuers to ensure that all events in the queue have
// been processed or cancelled. If the queue is nil, returns immediately.
func (q *EventQueue) WaitToBeDrained() {
	if q == nil {
		return
	}
	<-q.close

	// If the queue is running, then in-flight events may still be ongoing.
	// Wait for them to be completed for the queue to be fully drained. If the
	// queue is not running, we must forcefully run it because nothing else
	// will so that it can be drained.
	go q.run()
	<-q.eventsClosed
}

func (q *EventQueue) getLogger() *logrus.Entry {
	return log.WithFields(
		logrus.Fields{
			"name": q.name,
		})
}

// EventHandler is an interface for allowing an EventQueue to handle events
// in a generic way. To be processed by the EventQueue, all event types must
// implement any function specified in this interface.
type EventHandler interface {
	Handle(chan interface{})
}
