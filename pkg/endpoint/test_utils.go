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
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

// NewEndpointWithState creates a new endpoint useful for testing purposes
func NewEndpointWithState(owner regeneration.Owner, proxy EndpointProxy, allocator cache.IdentityAllocator, ID uint16, state string) *Endpoint {
	ep := &Endpoint{
		owner:           owner,
		proxy:           proxy,
		ID:              ID,
		OpLabels:        pkgLabels.NewOpLabels(),
		status:          NewEndpointStatus(),
		DNSHistory:      fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		state:           state,
		hasBPFProgram:   make(chan struct{}, 0),
		controllers:     controller.NewManager(),
		eventQueue:      eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", ID), option.Config.EndpointQueueSize),
		desiredPolicy:   policy.NewEndpointPolicy(owner.GetPolicyRepository()),
		regenFailedChan: make(chan struct{}, 1),
		allocator:       allocator,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx
	ep.startRegenerationFailureHandler()
	ep.realizedPolicy = ep.desiredPolicy

	ep.SetDefaultOpts(option.Config.Opts)
	ep.UpdateLogger(nil)

	ep.eventQueue.Run()

	return ep
}

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
			secID = e.SecurityIdentity
			e.runlock()
			if secID != nil {
				return secID
			}
		}
	}
}
