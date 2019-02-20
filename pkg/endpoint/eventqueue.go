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

import (
	"github.com/cilium/cilium/pkg/eventqueue"
)

// initializeEventQueue initializes the endpoint's event queue. Only one event
// queue can ever be initialized for the lifetime of a given endpoint
func (e *Endpoint) initializeEventQueue() {
	e.getLogger().Debug("starting endpoint event queue")
	go e.eventQueue.Run()
}

// Enqueue enqueues epEvent to the endpoint's EventQueue. It may block until
// the current event being processed by the endpoint's event queue is finished.
// If the event queue has been closed, then it is signalled to the event that
// the event is not ran (i.e., it has been "cancelled").
func (e *Endpoint) QueueEvent(epEvent *eventqueue.Event) {
	e.eventQueue.Enqueue(epEvent)
}

// Stop closes the event queue for the given endpoint if it hasn't
// been closed already. All events that are attempted to be queued up for the
// endpoint will be cancelled. This operation should only be performed when the
// endpoint is being deleted.
func (e *Endpoint) CloseEventQueue() {
	e.eventQueue.Stop()
}
