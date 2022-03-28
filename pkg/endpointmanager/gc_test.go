// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package endpointmanager

import (
	"context"
	"fmt"
	"time"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
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
		ep := endpoint.NewEndpointWithState(s, s, ipcache.NewIPCache(nil), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), id, endpoint.StateReady)
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
