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

// +build !privileged_tests

package endpoint

import (
	. "gopkg.in/check.v1"
)

func (s *EndpointSuite) TestEndpointState(c *C) {
	// new endpoint, no changes yet
	e := Endpoint{}
	c.Assert(e.State(), Equals, StateCreating)

	// resolving identity
	e = Endpoint{identityRevision: 1}
	c.Assert(e.State(), Equals, StateWaitingForIdentity)
	c.Assert(e.StateLocked(), Equals, StateWaitingForIdentity)
	c.Assert(e.ReadyToBuild(), Equals, false)

	// identity resolved, back to restored
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1}
	c.Assert(e.State(), Equals, StateCreating)
	c.Assert(e.ReadyToBuild(), Equals, true)

	// identity resolved, initial build queued
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{buildsQueued: 1}}
	c.Assert(e.State(), Equals, StateWaitingToRegenerate)
	c.Assert(e.BuildPendingLocked(), Equals, true)

	// identity resolved, initial build in progress
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{building: true}}
	c.Assert(e.State(), Equals, StateRegenerating)
	c.Assert(e.BuildPendingLocked(), Equals, false)

	// identity resolved, initial build successful
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{initialBuildSuccessful: true}}
	c.Assert(e.State(), Equals, StateReady)

	// restored endpoint
	e = Endpoint{state: state{restored: true}}
	c.Assert(e.State(), Equals, StateRestoring)

	// resolving identity
	e = Endpoint{identityRevision: 1, state: state{restored: true}}
	c.Assert(e.State(), Equals, StateWaitingForIdentity)

	// identity resolved, back to restored
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{restored: true}}
	c.Assert(e.State(), Equals, StateRestoring)

	// identity resolved, initial build queued
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{restored: true, buildsQueued: 1}}
	c.Assert(e.State(), Equals, StateWaitingToRegenerate)

	// identity resolved, initial build in progress
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{restored: true, building: true}}
	c.Assert(e.State(), Equals, StateRegenerating)

	// identity resolved, initial build successful
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{restored: true, initialBuildSuccessful: true}}
	c.Assert(e.State(), Equals, StateReady)

	// identity resolved, initial build successful, build failing
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{restored: true, initialBuildSuccessful: true, consecutiveBuildFailures: 1}}
	c.Assert(e.State(), Equals, StateNotReady)

	// disconnecting
	e = Endpoint{identityRevision: 1, realizedIdentityRevision: 1, state: state{restored: true, initialBuildSuccessful: true, disconnecting: true}}
	c.Assert(e.State(), Equals, StateDisconnecting)
}
