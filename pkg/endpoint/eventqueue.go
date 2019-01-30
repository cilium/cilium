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

package endpoint

type EventQueue struct {
	// This should be a buffered channel
	events chan *EndpointEvent
	close  chan struct{}
}

func newEventQueue() *EventQueue {
	return &EventQueue{
		// Only one event can be consumed per endpoint
		// at a time.
		events: make(chan *EndpointEvent, 1),
		close:  make(chan struct{}),
	}

}

// PolicyRevisionBumpEvent queues an event for the given endpoint to set its
// realized policy revision to rev. This may block depending on if events have
// been queued up for the given endpoint. It blocks until the event has
// succeeded, or if the event has been cancelled.
func (e *Endpoint) PolicyRevisionBumpEvent(rev uint64) {
	epBumpEvent := NewEndpointEvent(EndpointRevisionBumpEvent{Rev: rev})
	e.QueueEvent(epBumpEvent)
	select {
	case _ := <-epBumpEvent.EventResults:
		e.getLogger().Infof("bumped endpoint revision to %d", rev)
	case <-epBumpEvent.Cancelled:
	}
}

// initializeEventQueue is a wrapper around runEventQueue that ensures that each
// endpoint only has one event queue running at all times.
func (e *Endpoint) initializeEventQueue() {
	e.eventQueueOnce.Do(
		func() {
			e.runEventQueue()
		})
}

// QueueEvent enqueues epEvent to the endpoint's EventQueue. It may block until
// the current event being processed by the endpoint's event queue is finished.
// If the event queue has been closed, then it is signalled to the event that
// the event is not ran (i.e., it has been "cancelled").
func (e *Endpoint) QueueEvent(epEvent *EndpointEvent) {
	select {
	case <-e.eventQueue.close:
		close(epEvent.Cancelled)
	default:
		e.eventQueue.events <- epEvent
	}
}

// runEventQueue consumes events that have been queued for this endpoint. It
// is presumed that the eventQueue for an endpoint is a buffered channel with
// a length of one (i.e., only one event can be processed at a time). All
// business logic for handling queued events is contained within this function.
// Each event must be handled in such a way such that a result is sent across
// its EventResults channel, as the queuer of an event may be waiting on a
// result from the event. Otherwise, if the event queue is closed, then all
// events which were queued up are cancelled. It is assumed that the caller
// handles both cases (cancel, or result) gracefully.
func (e *Endpoint) runEventQueue() {
	for {
		e.getLogger().Debug("starting endpoint event queue")
		select {
		// Receive next event.
		case endpointEvent := <-e.eventQueue.events:
			{
				// Handle each event type.
				switch endpointEvent.EndpointEventMetadata.(type) {
				case EndpointRegenerationEvent:

					ev := endpointEvent.EndpointEventMetadata.(EndpointRegenerationEvent)
					e.getLogger().Debug("received endpoint regeneration event")

					err := e.regenerate(ev.owner, ev.regenContext)
					e.getLogger().Debug("sending endpoint regeneration result")
					regenResult := EndpointRegenerationResult{
						err: err,
					}
					endpointEvent.EventResults <- regenResult
				case EndpointRevisionBumpEvent:
					// TODO: if the endpoint is not in a 'ready' state that means that
					// we cannot set the policy revision, as something else has
					// changed endpoint state which necessitates regeneration,
					// *or* the endpoint is in a not-ready state (i.e., a prior
					// regeneration failed, so there is no way that we can
					// realize the policy revision yet. Should this be signaled
					// to the routine waiting for the result of this event?
					e.getLogger().Info("received endpoint revision bump event")
					ev := endpointEvent.EndpointEventMetadata.(EndpointRevisionBumpEvent)
					e.getLogger().Info("sending endpoint revision bump result")
					e.SetPolicyRevision(ev.Rev)
					endpointEvent.EventResults <- struct{}{}
				default:
					e.getLogger().Error("unsupported function type provided to Endpoint event queue")
				}

				// Ensures that no more results can be sent as the event has
				// already been processed.
				close(endpointEvent.EventResults)
			}
		// When the endpoint is deleted, cause goroutine which consumes events
		// from queue to exit via closing close channel.
		case <-e.eventQueue.close:
			{
				e.getLogger().Debug("closing endpoint event queue")

				// Drain queue of all events. This ensures that all events that
				// nothing blocks on an EventResult which will never be created.
				for drainEvent := range e.eventQueue.events {
					close(drainEvent.Cancelled)
				}
				close(e.eventQueue.events)
				return
			}
		}
	}
}

// CloseEventQueue closes the event queue for the given endpoint if it hasn't
// been closed already. All events that are attempted to be queued up for the
// endpoint will be cancelled. This operation should only be performed when the
// endpoint is being deleted.
func (e *Endpoint) CloseEventQueue() {
	select {
	case <-e.eventQueue.close:
		e.getLogger().Warning("tried to close event queue, but it already has been closed")
	default:
		e.getLogger().Debug("closing endpoint event queue")
		close(e.eventQueue.close)
	}
}
