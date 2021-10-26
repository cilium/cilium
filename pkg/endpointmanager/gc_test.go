// Copyright 2020 Authors of Cilium
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

package endpointmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	. "gopkg.in/check.v1"
)

// fakeCheck detects endpoints as unhealthy if they have an even EndpointID.
func fakeCheck(ep *endpoint.Endpoint) error {
	if ep.GetID()%2 == 0 {
		return fmt.Errorf("Endpoint has an even EndpointID")
	}
	return nil
}

func (s *EndpointManagerSuite) TestmarkAndSweep(c *C) {
	// Open-code WithPeriodicGC() to avoid running the controller
	mgr := NewEndpointManager(&dummyEpSyncher{})
	mgr.checkHealth = fakeCheck
	mgr.deleteEndpoint = endpointDeleteFunc(mgr.waitEndpointRemoved)

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	endpointIDToDelete := uint16(2)
	healthyEndpointIDs := []uint16{1, 3, 5, 7}
	allEndpointIDs := append(healthyEndpointIDs, endpointIDToDelete)
	for _, id := range allEndpointIDs {
		ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, testidentity.NewFakeIdentityAllocator(nil), id, endpoint.StateReady)
		mgr.expose(ep)
	}
	c.Assert(len(mgr.GetEndpoints()), Equals, len(allEndpointIDs))

	// Two-phase mark and sweep: Mark should not yet delete any endpoints.
	err := mgr.markAndSweep(ctx)
	c.Assert(mgr.EndpointExists(endpointIDToDelete), Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(mgr.GetEndpoints()), Equals, len(allEndpointIDs))

	// Second phase: endpoint should be marked now and we should only sweep
	// that particular endpoint.
	err = mgr.markAndSweep(ctx)
	c.Assert(mgr.EndpointExists(endpointIDToDelete), Equals, false)
	c.Assert(err, IsNil)
	c.Assert(len(mgr.GetEndpoints()), Equals, len(healthyEndpointIDs))
}
