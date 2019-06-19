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
	"github.com/cilium/cilium/api/v1/models"
)

// State is the state the endpoint is in
type State string

const (
	// StateCreating is used to set the endpoint is being created.
	StateCreating State = models.EndpointStateCreating

	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity State = models.EndpointStateWaitingForIdentity

	// StateReady specifies if the endpoint is ready to be used.
	StateReady State = models.EndpointStateReady

	// StateWaitingToRegenerate specifies when the endpoint needs to be regenerated, but regeneration has not started yet.
	StateWaitingToRegenerate State = models.EndpointStateWaitingToRegenerate

	// StateRegenerating specifies when the endpoint is being regenerated.
	StateRegenerating State = models.EndpointStateRegenerating

	// StateDisconnecting indicates that the endpoint is being disconnected
	StateDisconnecting State = models.EndpointStateDisconnecting

	// StateDisconnected is used to set the endpoint is disconnected.
	StateDisconnected State = models.EndpointStateDisconnected

	// StateRestoring is used to set the endpoint is being restored.
	StateRestoring State = models.EndpointStateRestoring
)

type state struct {
	// disconnecting is true when the endpoint is disconnecting, an
	// endpoint cannot transition out of disconnecting again
	disconnecting bool

	// building is true while the endpoint is being regenerated
	building bool

	// initialBuildSuccessful becomes true after the first build has been
	// successful
	initialBuildSuccessful bool

	// buildsQueued is the number of builds queued
	buildsQueued int

	// restored is true if the endpoint has been restored from disk
	restored bool
}

// BuildPendingLocked returns true if at least one build is currently pending
// with no build currently ongoing
func (e *Endpoint) BuildPendingLocked() bool {
	return e.state.buildsQueued > 0 && !e.state.building
}

// ReadyToBuild returns true if the endpoint is in a state where it can be built
func (e *Endpoint) ReadyToBuild() bool {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.realizedIdentityRevision > 0 && !e.state.disconnecting
}

// State returns the state of the endpoint
func (e *Endpoint) State() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.StateLocked()
}

// StateLocked returns the state of the endpoint if the endpoint is already
// locked
func (e *Endpoint) StateLocked() string {
	switch {
	case e.state.disconnecting:
		return StateDisconnecting

	case e.state.building:
		return StateRegenerating

	case e.identityRevision > e.realizedIdentityRevision:
		return StateWaitingForIdentity

	case e.state.restored && !e.state.initialBuildSuccessful:
		return StateRestoring

	case e.state.buildsQueued > 0:
		return StateWaitingToRegenerate

	case !e.state.initialBuildSuccessful:
		return StateCreating

	default:
		return StateReady
	}
}

func (e *Endpoint) setBuilding(value bool) {
	e.UnconditionalLock()
	e.state.building = value
	e.Unlock()
}

// StartDisconnectingLocked starts to disconnect the endpoint. e.Mutex must be
// held.
func (e *Endpoint) StartDisconnectingLocked(reason string) {
	e.state.disconnecting = true
	e.logStatusLocked(Other, OK, "Disconnecting: "+reason)
}

// isDisconnectingLocked returns true if the endpoint is being disconnected or
// already disconnected
//
// This function must be called after re-acquiring the endpoint mutex to verify
// that the endpoint has not been removed in the meantime.
//
// endpoint.mutex must be held in read mode at least
func (e *Endpoint) isDisconnectingLocked() bool {
	return e.state.disconnecting
}
