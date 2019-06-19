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

type State string

const (
	// StateCreating is used to set the endpoint is being created.
	StateCreating = string(models.EndpointStateCreating)

	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity = string(models.EndpointStateWaitingForIdentity)

	// StateReady specifies if the endpoint is ready to be used.
	StateReady = string(models.EndpointStateReady)

	// StateWaitingToRegenerate specifies when the endpoint needs to be regenerated, but regeneration has not started yet.
	StateWaitingToRegenerate = string(models.EndpointStateWaitingToRegenerate)

	// StateRegenerating specifies when the endpoint is being regenerated.
	StateRegenerating = string(models.EndpointStateRegenerating)

	// StateDisconnecting indicates that the endpoint is being disconnected
	StateDisconnecting = string(models.EndpointStateDisconnecting)

	// StateDisconnected is used to set the endpoint is disconnected.
	StateDisconnected = string(models.EndpointStateDisconnected)

	// StateRestoring is used to set the endpoint is being restored.
	StateRestoring = string(models.EndpointStateRestoring)
)

type state struct {
	disconnecting bool

	// building is true while the endpoint is being regenerated
	building bool

	// initialBuildSuccessful becomes true after the first build has been
	// successful
	initialBuildSuccessful bool

	// buildsQueued is the number of builds queued
	buildsQueued int

	restored bool
}

func (e *Endpoint) BuildPendingLocked() bool {
	return e.state.buildsQueued > 0 && !e.state.building
}

func (e *Endpoint) ReadyToBuild() bool {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.realizedIdentityRevision > 0
}

func (e *Endpoint) State() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.StateLocked()
}

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

func (e *Endpoint) setStateLocked(toState, reason string) {
	//	fromState := e.state
	//
	//	if fromState == StateDisconnecting && toState != StateDisconnected {
	//		e.Logger().Error("Invalid state change attempted. Endpoint is disconnecting")
	//		return
	//	}
	//
	//	e.state = toState
	//	e.logStatusLocked(Other, OK, reason)
}
