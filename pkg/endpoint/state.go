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
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/metrics"
)

// State is the state the endpoint is in
type State string

// String returns the string representation
func (s State) String() string {
	return string(s)
}

const (
	// StateUnspecified is used when the state is not known
	StateUnspecified = ""

	// StateCreating is used to set the endpoint is being created.
	StateCreating = State(models.EndpointStateCreating)

	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity = State(models.EndpointStateWaitingForIdentity)

	// StateReady specifies if the endpoint is ready to be used.
	StateReady = State(models.EndpointStateReady)

	// StateWaitingToRegenerate specifies when the endpoint needs to be regenerated, but regeneration has not started yet.
	StateWaitingToRegenerate = State(models.EndpointStateWaitingToRegenerate)

	// StateRegenerating specifies when the endpoint is being regenerated.
	StateRegenerating = State(models.EndpointStateRegenerating)

	// StateDisconnecting indicates that the endpoint is being disconnected
	StateDisconnecting = State(models.EndpointStateDisconnecting)

	// StateDisconnected is used to set the endpoint is disconnected.
	StateDisconnected = State(models.EndpointStateDisconnected)

	// StateRestoring is used to set the endpoint is being restored.
	StateRestoring = State(models.EndpointStateRestoring)

	// StateNotReady indicates that the endpoint build is currently failing
	StateNotReady = State(models.EndpointStateNotReady)
)

type state struct {
	// disconnecting is true when the endpoint is disconnecting, an
	// endpoint cannot transition out of disconnecting again
	disconnecting bool

	// disconnected is the final state, it is true once when the endpoint
	// is fully disconnected
	disconnected bool

	// building is true while the endpoint is being regenerated
	building bool

	// initialBuildSuccessful becomes true after the first build has been
	// successful
	initialBuildSuccessful bool

	// buildsQueued is the number of builds queued
	buildsQueued int

	// restored is true if the endpoint has been restored from disk
	restored bool

	// initialStateTransitionDone is true after the first initial state
	// transition
	initialStateTransitionDone bool

	// consecutiveBuildFailures is the number of build failures in a row
	consecutiveBuildFailures int

	// lastBuildError is the error message of the last build failure or nil
	// if the last build succeeded
	lastBuildError error
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
func (e *Endpoint) State() State {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.StateLocked()
}

// StateLocked returns the state of the endpoint if the endpoint is already
// locked
func (e *Endpoint) StateLocked() State {
	switch {
	case e.state.disconnected:
		return StateDisconnected

	case e.state.disconnecting:
		return StateDisconnecting

	case e.state.building:
		return StateRegenerating

	case e.identityRevision > e.realizedIdentityRevision:
		return StateWaitingForIdentity

	case e.state.buildsQueued > 0:
		return StateWaitingToRegenerate

	case !e.state.initialBuildSuccessful:
		if e.state.restored {
			return StateRestoring
		}

		return StateCreating

	case e.state.consecutiveBuildFailures > 0 || e.state.lastBuildError != nil:
		return StateNotReady

	default:
		return StateReady
	}
}

// setBuilding is used to indicate whether the endpoint is currently being
// built/regenerated. Note that this only includes the actual regeneration, not
// the time in which the endpoint is queued and waiting to be regenerated.
func (e *Endpoint) setBuilding(value bool, reason string) {
	e.UnconditionalLock()
	oldState := e.StateLocked()
	e.state.building = value
	e.postStateModificationLocked(oldState, reason)
	e.Unlock()
}

// markRestored is called to mark an endpoint to have been restored
func (e *Endpoint) markRestoredLocked() {
	oldState := e.StateLocked()
	e.state.restored = true
	e.postStateModificationLocked(oldState, "Restoring endpoint from state")
}

// buildQueued is called each time an endpoint build has been queued
func (e *Endpoint) buildQueued(reason string) {
	e.UnconditionalLock()
	oldState := e.StateLocked()
	e.state.buildsQueued++
	e.postStateModificationLocked(oldState, reason)
	e.Unlock()
}

// buildDone is called after each successful, unsuccessful or cancelled
// endpoint build/regeneration
func (e *Endpoint) buildDone(success, cancelled bool, buildError error) {
	e.UnconditionalLock()
	oldState := e.StateLocked()
	e.state.building = false
	if success || !cancelled {
		e.state.initialBuildSuccessful = true
	}
	e.state.buildsQueued--

	switch {
	case success:
		e.state.lastBuildError = nil
		e.state.consecutiveBuildFailures = 0
		e.postStateModificationLocked(oldState, "Build successful")
	case cancelled:
		e.state.lastBuildError = fmt.Errorf("build timed out")
		e.state.consecutiveBuildFailures++
		e.postStateModificationLocked(oldState, "Build timed out")
	case buildError != nil:
		e.state.lastBuildError = buildError
		e.state.consecutiveBuildFailures++
		e.postStateModificationLocked(oldState, "Build failed: "+buildError.Error())
	default:
		e.state.lastBuildError = fmt.Errorf("unspecified build error")
		e.state.consecutiveBuildFailures++
		e.postStateModificationLocked(oldState, "Build failed without error")
	}
	e.Unlock()
}

// StartDisconnectingLocked starts to disconnect the endpoint. e.Mutex must be
// held.
func (e *Endpoint) StartDisconnectingLocked(reason string) {
	oldState := e.StateLocked()
	e.state.disconnecting = true
	e.postStateModificationLocked(oldState, reason)
}

// markDisconnected marks the endpoint as disconnected
func (e *Endpoint) markDisconnectedLocked() {
	oldState := e.StateLocked()
	e.state.disconnected = true
	e.postStateModificationLocked(oldState, "")
}

// bumpIdentityRevisionLocked is called to indicate that identity relevant
// labels may have changed and the identity must be resolved
func (e *Endpoint) bumpIdentityRevisionLocked(reason string) int {
	oldState := e.StateLocked()
	e.identityRevision++
	e.postStateModificationLocked(oldState, "%s, new identity revision is %d", reason, e.identityRevision)
	return e.identityRevision
}

// markIdentityRevisionResolvedLocked is called when an identity has been
// resolved. The revision number provided must be the revision returned from
// bumpIdentityRevisionLocked() at the time the labels have changed.
func (e *Endpoint) markIdentityRevisionResolvedLocked(rev int) {
	if rev > e.realizedIdentityRevision {
		oldState := e.StateLocked()
		e.realizedIdentityRevision = rev
		e.postStateModificationLocked(oldState, "Resolved identity revision %d to identity %d", rev, e.SecurityIdentity.ID)
	}
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

// postStateModificationLocked must be called after any endpoint field is
// changed which may modify the endpoint's state
func (e *Endpoint) postStateModificationLocked(oldState State, reason string, args ...interface{}) {
	newState := e.StateLocked()

	e.logStatusLocked(Info, oldState, reason, args...)

	if e.state.initialStateTransitionDone {
		metrics.EndpointStateCount.WithLabelValues(oldState.String()).Dec()
	} else {
		e.state.initialStateTransitionDone = true
	}

	// Since StateDisconnected is the final state, after which the
	// endpoint is gone, we should not increment metrics for this state.
	if newState != StateDisconnected {
		metrics.EndpointStateCount.WithLabelValues(newState.String()).Inc()
	}
}

// GetHealthModel returns the endpoint's health object.
//
// Must be called with e.Mutex locked or read-locked
func (e *Endpoint) getHealthModel() (h *models.EndpointHealth) {
	h = &models.EndpointHealth{
		Bpf:           models.EndpointHealthStatusDisabled,
		Policy:        models.EndpointHealthStatusDisabled,
		Connected:     e.state.initialBuildSuccessful || e.state.restored,
		OverallHealth: models.EndpointHealthStatusDisabled,
	}

	if e.state.disconnecting || e.state.disconnected {
		return
	}

	switch {
	case e.state.lastBuildError != nil:
		h.Bpf = models.EndpointHealthStatusWarning
		h.Policy = models.EndpointHealthStatusWarning
		h.OverallHealth = models.EndpointHealthStatusWarning
	case !e.state.initialBuildSuccessful:
		h.Bpf = models.EndpointHealthStatusPending
		h.Policy = models.EndpointHealthStatusPending
		h.OverallHealth = models.EndpointHealthStatusPending
	default:
		h.Bpf = models.EndpointHealthStatusOK
		h.Policy = models.EndpointHealthStatusOK
		h.OverallHealth = models.EndpointHealthStatusOK
	}

	return
}
