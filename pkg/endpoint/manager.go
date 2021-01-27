// Copyright 2016-2019 Authors of Cilium
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
	"fmt"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type endpointManager interface {
	RemoveReferences(id.Identifiers)
	RemoveID(uint16)
	ReleaseID(*Endpoint) error
	RemoveIPv6Address(addressing.CiliumIPv6)
}

// Start assigns a Cilium Endpoint ID to the endpoint and prepares it to
// receive events from other subsystems.
//
// The endpoint must not already be exposed via the endpointmanager prior to
// calling Start(), as it assumes unconditional access over the Endpoint
// object.
func (e *Endpoint) Start(id uint16) {
	// No need to check liveness as an endpoint can only be deleted via the
	// API after it has been inserted into the manager.
	// 'e.ID' written below, read lock is not enough.
	e.unconditionalLock()
	defer e.unlock()

	e.ID = id
	e.UpdateLogger(map[string]interface{}{
		logfields.EndpointID: e.ID,
	})

	// Start goroutines that are responsible for handling events.
	e.startRegenerationFailureHandler()
	if e.eventQueue == nil {
		e.InitEventQueue()
	}
	e.eventQueue.Run()
	e.getLogger().Info("New endpoint")
}

func (e *Endpoint) removeReferences(mgr endpointManager) {
	refs := e.IdentifiersLocked()
	mgr.RemoveReferences(refs)
}

// Unexpose removes the endpoint from being globally acccessible via other
// packages.
func (e *Endpoint) Unexpose(mgr endpointManager) <-chan struct{} {
	epRemoved := make(chan struct{})

	// This must be done before the ID is released for the endpoint!
	mgr.RemoveID(e.ID)

	mgr.RemoveIPv6Address(e.IPv6)

	go func(ep *Endpoint) {
		err := mgr.ReleaseID(ep)
		if err != nil {
			// While restoring, endpoint IDs may not have been reused yet.
			// Failure to release means that the endpoint ID was not reused
			// yet.
			//
			// While endpoint is disconnecting, ID is already available in ID cache.
			//
			// Avoid irritating warning messages.
			state := ep.GetState()
			if state != StateRestoring && state != StateDisconnecting && state != StateDisconnected {
				log.WithError(err).WithField("state", state).Warning("Unable to release endpoint ID")
			}
		}

		close(epRemoved)
	}(e)
	e.removeReferences(mgr)
	return epRemoved
}

// InitEventQueue initializes the endpoint's event queue. Note that this
// function does not begin processing events off the queue, as that's left up
// to the caller to call Expose in order to allow other subsystems to access
// the endpoint. This function assumes that the endpoint ID has already been
// allocated!
//
// Having this be a separate function allows us to prepare
// the event queue while the endpoint is being validated (during restoration)
// so that when its metadata is resolved, events can be enqueued (such as
// visibility policy and bandwidth policy).
func (e *Endpoint) InitEventQueue() {
	e.eventQueue = eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", e.ID), option.Config.EndpointQueueSize)
}
