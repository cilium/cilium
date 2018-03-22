// Copyright 2018 Authors of Cilium
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
	"runtime"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

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

// GetState returns the endpoint's state
// endpoint.Mutex may only be RLock()ed
func (e *Endpoint) GetStateLocked() string {
	return e.state
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be RLock()ed
func (e *Endpoint) GetState() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	return e.GetStateLocked()
}

// SetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// Returns true only if endpoints state was changed as requested
func (e *Endpoint) SetStateLocked(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateCreating:
		switch toState {
		case StateDisconnecting, StateWaitingForIdentity:
			goto OKState
		}
	case StateWaitingForIdentity:
		switch toState {
		case StateReady, StateDisconnecting:
			goto OKState
		}
	case StateReady:
		switch toState {
		case StateDisconnecting, StateWaitingToRegenerate:
			goto OKState
		}
	case StateDisconnecting:
		switch toState {
		case StateDisconnected:
			goto OKState
		}
	case StateDisconnected:
		// No valid transitions, as disconnected is a terminal state for the endpoint.
	case StateWaitingToRegenerate:
		switch toState {
		// Note that transitions to waiting-to-regenerate state
		case StateDisconnecting:
			goto OKState
		}
	case StateRegenerating:
		switch toState {
		// Even while the endpoint is regenerating it is
		// possible that further changes require a new
		// build. In this case the endpoint is transitioned
		// from the regenerating state to
		// waiting-to-regenerate state.
		case StateDisconnecting, StateWaitingToRegenerate:
			goto OKState
		}
	case StateRestoring:
		switch toState {
		case StateDisconnecting, StateWaitingToRegenerate:
			goto OKState
		}
	}
	if toState != fromState {
		_, fileName, fileLine, _ := runtime.Caller(1)
		e.getLogger().WithFields(logrus.Fields{
			logfields.EndpointState + ".from": fromState,
			logfields.EndpointState + ".to":   toState,
			"file": fileName,
			"line": fileLine,
		}).Info("Invalid state transition skipped")
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)
	return true
}

// BuilderSetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// endpoint BuildMutex must be held!
func (e *Endpoint) BuilderSetStateLocked(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateCreating, StateWaitingForIdentity, StateReady, StateDisconnecting, StateDisconnected:
		// No valid transitions for the builder
	case StateWaitingToRegenerate:
		switch toState {
		// Builder transitions the endpoint from
		// waiting-to-regenerate state to regenerating state
		// right after aquiring the endpoint lock, and while
		// endpoint's build mutex is held. All changes to
		// cilium and endpoint configuration, policy as well
		// as the existing set of security identities will be
		// reconsidered after this point, i.e., even if some
		// of them are changed regeneration need not be queued
		// if the endpoint is already in waiting-to-regenerate
		// state.
		case StateRegenerating:
			goto OKState
		}
	case StateRegenerating:
		switch toState {
		// While still holding the build mutex, the builder
		// tries to transition the endpoint to ready
		// state. But since the endpoint mutex was released
		// for the duration of the bpf generation, it is
		// possible that another build request has been
		// queued. In this case the endpoint has been
		// transitioned to waiting-to-regenerate state
		// already, and the transition to ready state is
		// skipped.
		case StateReady:
			goto OKState
		}
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)
	return true
}
