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
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"

	. "gopkg.in/check.v1"
)

// WaitForIdentity waits for up to timeoutDuration amount of time for the
// endpoint to have an identity. If the timeout is reached, returns nil.
func (e *Endpoint) WaitForIdentity(timeoutDuration time.Duration) *identity.Identity {
	timeout := time.NewTimer(timeoutDuration)
	defer timeout.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	var secID *identity.Identity
	for {
		select {
		case <-timeout.C:
			return nil
		case <-tick.C:
			e.unconditionalRLock()
			secID = e.securityIdentity
			e.runlock()
			if secID != nil {
				return secID
			}
		}
	}
}

// PrepareEndpointForTesting creates an endpoint useful for testing purposes.
func PrepareEndpointForTesting(owner regeneration.Owner, proxy EndpointProxy, id uint16, identity *identity.Identity, ipv4 addressing.CiliumIPv4, ipv6 addressing.CiliumIPv6) *Endpoint {
	e := NewEndpointWithState(owner, proxy, id, StateWaitingForIdentity)
	e.ipv6 = ipv6
	e.ipv4 = ipv4
	e.setIdentity(identity, true)

	e.unconditionalLock()
	e.setState(StateWaitingToRegenerate, "test")
	e.unlock()
	return e
}

func (e *Endpoint) RegenerateEndpointTest(c *C, regenMetadata *regeneration.ExternalRegenerationMetadata) {
	e.unconditionalLock()
	ready := e.setState(StateWaitingToRegenerate, "test")
	e.unlock()
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(regenMetadata)
	c.Assert(buildSuccess, Equals, true)
}
