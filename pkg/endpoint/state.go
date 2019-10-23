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
	"runtime"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
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

// getState returns the endpoint's state
// endpoint.Mutex may only be.rlockAlive()ed
func (e *Endpoint) getState() string {
	return e.state
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be.rlockAlive()ed
func (e *Endpoint) GetState() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.getState()
}

// SetState modifies the endpoint's state. Returns true only if endpoints state
// was changed as requested
func (e *Endpoint) SetState(toState, reason string) bool {
	e.unconditionalLock()
	defer e.unlock()

	return e.setState(toState, reason)
}

func (e *Endpoint) setState(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state

	switch fromState { // From state
	case "": // Special case for capturing initial state transitions like
		// nil --> StateWaitingForIdentity, StateRestoring
		switch toState {
		case StateWaitingForIdentity, StateRestoring:
			goto OKState
		}
	case StateCreating:
		switch toState {
		case StateDisconnecting, StateWaitingForIdentity, StateRestoring:
			goto OKState
		}
	case StateWaitingForIdentity:
		switch toState {
		case StateReady, StateDisconnecting:
			goto OKState
		}
	case StateReady:
		switch toState {
		case StateWaitingForIdentity, StateDisconnecting, StateWaitingToRegenerate, StateRestoring:
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
		// Note that transitions to StateWaitingToRegenerate are not allowed,
		// as callers of this function enqueue regenerations if 'true' is
		// returned. We don't want to return 'true' for the case of
		// transitioning to StateWaitingToRegenerate, as this means that a
		// regeneration is already queued up. Callers would then queue up
		// another unneeded regeneration, which is undesired.
		case StateWaitingForIdentity, StateDisconnecting, StateRestoring:
			goto OKState
		// Don't log this state transition being invalid below so that we don't
		// put warnings in the logs for a case which does not result in incorrect
		// behavior.
		case StateWaitingToRegenerate:
			return false
		}
	case StateRegenerating:
		switch toState {
		// Even while the endpoint is regenerating it is
		// possible that further changes require a new
		// build. In this case the endpoint is transitioned
		// from the regenerating state to
		// waiting-for-identity or waiting-to-regenerate state.
		case StateWaitingForIdentity, StateDisconnecting, StateWaitingToRegenerate, StateRestoring:
			goto OKState
		}
	case StateRestoring:
		switch toState {
		case StateDisconnecting, StateRestoring:
			goto OKState
		}
	}
	if toState != fromState {
		_, fileName, fileLine, _ := runtime.Caller(1)
		e.getLogger().WithFields(logrus.Fields{
			logfields.EndpointState + ".from": fromState,
			logfields.EndpointState + ".to":   toState,
			"file":                            fileName,
			"line":                            fileLine,
		}).Info("Invalid state transition skipped")
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)

	if fromState != "" {
		metrics.EndpointStateCount.
			WithLabelValues(fromState).Dec()
	}

	// Since StateDisconnected is the final state, after which the
	// endpoint is gone, we should not increment metrics for this state.
	if toState != "" && toState != StateDisconnected {
		metrics.EndpointStateCount.
			WithLabelValues(toState).Inc()
	}
	return true
}

// BuilderSetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// endpoint buildMutex must be held!
func (e *Endpoint) BuilderSetStateLocked(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateCreating, StateWaitingForIdentity, StateReady, StateDisconnecting, StateDisconnected:
		// No valid transitions for the builder
	case StateWaitingToRegenerate, StateRestoring:
		switch toState {
		// Builder transitions the endpoint from
		// waiting-to-regenerate state to regenerating state
		// right after acquiring the endpoint lock, and while
		// endpoint's build mutex is held. All changes to
		// cilium and endpoint configuration, policy as well
		// as the existing set of security identities will be
		// reconsidered after this point, i.e., even if some
		// of them are changed regeneration need not be queued
		// if the endpoint is already in waiting-to-regenerate
		// state.
		case StateRegenerating:
			goto OKState
		// Transition to ReadyState is not supported, but is
		// attempted when a regeneration is competed, and another
		// regeneration has been queued in the meanwhile. So this
		// is expected and will not be logged as an error or warning.
		case StateReady:
			return false
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
		// skipped (but not worth logging for, as this is
		// normal, see above).
		case StateReady:
			goto OKState
		}
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)

	if fromState != "" {
		metrics.EndpointStateCount.
			WithLabelValues(fromState).Dec()
	}

	// Since StateDisconnected is the final state, after which the
	// endpoint is gone, we should not increment metrics for this state.
	if toState != "" && toState != StateDisconnected {
		metrics.EndpointStateCount.
			WithLabelValues(toState).Inc()
	}
	return true
}

// IsDisconnecting returns true if the endpoint is being disconnected or
// already disconnected
//
// This function must be called after re-acquiring the endpoint mutex to verify
// that the endpoint has not been removed in the meantime.
//
// endpoint.mutex must be held in read mode at least
func (e *Endpoint) IsDisconnecting() bool {
	return e.state == StateDisconnected || e.state == StateDisconnecting
}
