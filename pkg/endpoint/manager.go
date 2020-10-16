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
	AllocateID(id uint16) (uint16, error)
	RunK8sCiliumEndpointSync(*Endpoint, EndpointStatusConfiguration)
	UpdateReferences(map[id.PrefixType]string, *Endpoint)
	UpdateIDReference(*Endpoint)
	RemoveReferences(map[id.PrefixType]string)
	RemoveID(uint16)
	ReleaseID(*Endpoint) error
	AddIPv6Address(addressing.CiliumIPv6)
	RemoveIPv6Address(addressing.CiliumIPv6)
}

// Expose exposes the endpoint to the endpointmanager. After this function
// is called, the endpoint may be accessed by any lookup in the endpointmanager.
func (e *Endpoint) Expose(mgr endpointManager) error {
	// No need to check liveness as an endpoint can only be deleted via the
	// API after it has been inserted into the manager.
	// 'e.ID' written below, read lock is not enough.
	e.unconditionalLock()

	newID, err := mgr.AllocateID(e.ID)
	if err != nil {
		e.unlock()
		return err
	}

	e.ID = newID
	e.UpdateLogger(map[string]interface{}{
		logfields.EndpointID: e.ID,
	})

	e.startRegenerationFailureHandler()
	// Now that the endpoint has its ID, it can be created with a name based on
	// its ID, and its eventqueue can be safely started. Ensure that it is only
	// started once it is exposed to the endpointmanager so that it will be
	// stopped when the endpoint is removed from the endpointmanager.
	if e.eventQueue == nil {
		e.InitEventQueue()
	}
	e.eventQueue.Run()

	mgr.AddIPv6Address(e.IPv6)

	// No need to check liveness as an endpoint can only be deleted via the
	// API after it has been inserted into the manager.
	mgr.UpdateIDReference(e)
	e.updateReferences(mgr)
	e.getLogger().Info("New endpoint")
	e.unlock()

	mgr.RunK8sCiliumEndpointSync(e, option.Config)
	return nil
}

// UpdateReferences updates the endpointmanager mappings of identifiers to
// endpoints for the given endpoint. Returns an error if the endpoint is
// being deleted.
func (e *Endpoint) UpdateReferences(mgr endpointManager) error {
	if err := e.rlockAlive(); err != nil {
		return err
	}
	defer e.runlock()
	e.updateReferences(mgr)
	return nil
}

func (e *Endpoint) updateReferences(mgr endpointManager) {
	refs := e.generateReferences()
	mgr.UpdateReferences(refs, e)
}

func (e *Endpoint) generateReferences() map[id.PrefixType]string {
	refs := make(map[id.PrefixType]string, 6)
	if e.containerID != "" {
		refs[id.ContainerIdPrefix] = e.containerID
	}

	if e.dockerEndpointID != "" {
		refs[id.DockerEndpointPrefix] = e.dockerEndpointID
	}

	if e.IPv4.IsSet() {
		refs[id.IPv4Prefix] = e.IPv4.String()
	}

	if e.IPv6.IsSet() {
		refs[id.IPv6Prefix] = e.IPv6.String()
	}

	if e.containerName != "" {
		refs[id.ContainerNamePrefix] = e.containerName
	}

	if podName := e.getK8sNamespaceAndPodName(); podName != "" {
		refs[id.PodNamePrefix] = podName
	}
	return refs
}

func (e *Endpoint) removeReferences(mgr endpointManager) {
	refs := e.generateReferences()
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

		// The endpoint's EventQueue may not be stopped yet (depending on whether
		// the caller of the EventQueue has stopped it or not). Call it here
		// to be safe so that ep.WaitToBeDrained() does not hang forever.
		ep.eventQueue.Stop()

		// Wait for no more events (primarily regenerations) to be occurring for
		// this endpoint.
		ep.eventQueue.WaitToBeDrained()

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
