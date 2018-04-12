// Copyright 2016-2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
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
