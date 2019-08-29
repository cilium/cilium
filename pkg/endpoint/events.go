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
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

// EndpointRegenerationEvent contains all fields necessary to regenerate an endpoint.
type EndpointRegenerationEvent struct {
	regenContext *regenerationContext
	ep           *Endpoint
}

// Handle handles the regeneration event for the endpoint.
func (ev *EndpointRegenerationEvent) Handle(res chan interface{}) {
	e := ev.ep
	regenContext := ev.regenContext

	err := e.RLockAlive()
	if err != nil {
		e.LogDisconnectedMutexAction(err, "before regeneration")
		res <- &EndpointRegenerationResult{
			err: err,
		}

		return
	}
	e.RUnlock()

	// We should only queue the request after we use all the endpoint's
	// lock/unlock. Otherwise this can get a deadlock if the endpoint is
	// being deleted at the same time. More info PR-1777.
	doneFunc, err := e.owner.QueueEndpointBuild(regenContext.parentContext, uint64(e.ID))
	if err != nil {
		e.getLogger().WithError(err).Warning("unable to queue endpoint build")
	} else if doneFunc != nil {
		e.getLogger().Debug("Dequeued endpoint from build queue")

		regenContext.DoneFunc = doneFunc

		err = ev.ep.regenerate(ev.regenContext)

		doneFunc()
		e.notifyEndpointRegeneration(err)
	} else {
		// If another build has been queued for the endpoint, that means that
		// that build will be able to take care of all of the work needed to
		// regenerate the endpoint at this current point in time; queueing
		// another build is a waste of resources.
		e.getLogger().Debug("build not queued for endpoint because another build has already been queued")
	}

	res <- &EndpointRegenerationResult{
		err: err,
	}
	return
}

// EndpointRegenerationResult contains the results of an endpoint regeneration.
type EndpointRegenerationResult struct {
	err error
}

// EndpointRevisionBumpEvent contains all fields necessary to bump the policy
// revision of a given endpoint.
type EndpointRevisionBumpEvent struct {
	Rev uint64
	ep  *Endpoint
}

// Handle handles the revision bump event for the Endpoint.
func (ev *EndpointRevisionBumpEvent) Handle(res chan interface{}) {
	// TODO: if the endpoint is not in a 'ready' state that means that
	// we cannot set the policy revision, as something else has
	// changed endpoint state which necessitates regeneration,
	// *or* the endpoint is in a not-ready state (i.e., a prior
	// regeneration failed, so there is no way that we can
	// realize the policy revision yet. Should this be signaled
	// to the routine waiting for the result of this event?
	ev.ep.SetPolicyRevision(ev.Rev)
	res <- struct{}{}
}

// PolicyRevisionBumpEvent queues an event for the given endpoint to set its
// realized policy revision to rev. This may block depending on if events have
// been queued up for the given endpoint. It blocks until the event has
// succeeded, or if the event has been cancelled.
func (e *Endpoint) PolicyRevisionBumpEvent(rev uint64) {
	epBumpEvent := eventqueue.NewEvent(&EndpointRevisionBumpEvent{Rev: rev, ep: e})
	// Don't check policy revision event results - it is best effort.
	_, err := e.eventQueue.Enqueue(epBumpEvent)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.PolicyRevision: rev,
			logfields.EndpointID:     e.ID,
		}).Errorf("enqueue of EndpointRevisionBumpEvent failed: %s", err)
	}
}
