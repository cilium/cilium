// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
)

// fakeCheck detects endpoints as unhealthy if they have an even EndpointID.
func fakeCheck(ep *endpoint.Endpoint) error {
	if ep.GetID()%2 == 0 {
		return fmt.Errorf("Endpoint has an even EndpointID")
	}
	return nil
}

// fakeCheckHealthy detects endpoints as healthy
func fakeCheckHealthy(ep *endpoint.Endpoint) error {
	return nil
}

func TestMarkAndSweep(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	// Open-code WithPeriodicGC() to avoid running the controller
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	mgr.checkHealth = fakeCheck
	mgr.deleteEndpoint = endpointDeleteFunc(mgr.waitEndpointRemoved)

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	endpointIDToDelete := uint16(2)
	healthyEndpointIDs := []uint16{1, 3, 5, 7}
	allEndpointIDs := append(healthyEndpointIDs, endpointIDToDelete)
	for _, id := range allEndpointIDs {
		model := newTestEndpointModel(int(id), endpoint.StateReady)
		ep, err := endpoint.NewEndpointFromChangeModel(makeTestEndpointParams(logger, s.repo), nil, &endpoint.FakeEndpointProxy{}, model, nil)
		require.NoError(t, err)

		ep.Start(uint16(model.ID))
		t.Cleanup(ep.Stop)

		err = mgr.expose(ep)
		require.NoError(t, err)
	}
	require.Len(t, mgr.GetEndpoints(), len(allEndpointIDs))

	// Two-phase mark and sweep: Mark should not yet delete any endpoints.
	err := mgr.markAndSweep(ctx)
	require.True(t, mgr.EndpointExists(endpointIDToDelete))
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), len(allEndpointIDs))

	// Second phase: endpoint should be marked now and we should only sweep
	// that particular endpoint.
	err = mgr.markAndSweep(ctx)
	require.False(t, mgr.EndpointExists(endpointIDToDelete))
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), len(healthyEndpointIDs))
}

// TestMarkAndSweepNoDoubleSweep verifies that the sweep-first-then-mark logic ensures
// an endpoint is only swept once.
func TestMarkAndSweepNoDoubleSweep(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	mgr.checkHealth = fakeCheck
	mgr.deleteEndpoint = endpointDeleteFunc(mgr.waitEndpointRemoved)

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	testEPID := 256

	// Create an unhealthy endpoint (even ID)
	unhealthyID := uint16(testEPID)
	model := newTestEndpointModel(int(unhealthyID), endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(makeTestEndpointParams(logger, s.repo), nil, &endpoint.FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)
	ep.Start(unhealthyID)
	t.Cleanup(ep.Stop)
	err = mgr.expose(ep)
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), 1)

	// Round 1 GC: sweep is empty, mark tags the unhealthy endpoint
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.True(t, mgr.EndpointExists(unhealthyID), "endpoint should still exist after round 1 GC")
	require.Len(t, mgr.GetEndpoints(), 1)

	// Round 2 GC: sweep deletes the previously marked endpoint,
	// mark re-checks (endpoint has been deleted at this point)
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.False(t, mgr.EndpointExists(unhealthyID), "endpoint should be deleted after round 2 GC")
	require.Empty(t, mgr.GetEndpoints(), "endpoint should be deleted after round 2 GC")

	// Verify that markedEndpoints is correctly cleared after sweep.
	// Since we sweep first then mark, after round 2 sweep executes,
	// the endpoint no longer exists during the mark phase,
	// so markedEndpoints should be empty.
	require.False(t, mgr.isMarkedEndpoint(unhealthyID), "markedEndpoints should be empty after endpoint is deleted")

	// Simulate endpoint ID reuse: create a new healthy endpoint.
	// Since fakeCheck marks even IDs as unhealthy, we use an odd ID
	// to simulate a healthy endpoint.
	healthyID := uint16(testEPID)
	model2 := newTestEndpointModel(int(healthyID), endpoint.StateReady)
	ep2, err := endpoint.NewEndpointFromChangeModel(makeTestEndpointParams(logger, s.repo), nil, &endpoint.FakeEndpointProxy{}, model2, nil)
	require.NoError(t, err)
	ep2.Start(healthyID)
	t.Cleanup(ep2.Stop)
	err = mgr.expose(ep2)
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), 1)

	// Round 3 GC: since markedEndpoints is empty, sweep won't delete any endpoint.
	// The newly created healthy endpoint should not be incorrectly deleted.
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.True(t, mgr.EndpointExists(healthyID), "healthy endpoint should still exist after round 3 GC")
	require.Len(t, mgr.GetEndpoints(), 1)

	// Verify that healthyID (256, even) is now marked in markedEndpoints after round 3.
	require.True(t, mgr.isMarkedEndpoint(healthyID), "healthyID should be marked in markedEndpoints after round 3 GC")

	// Round 4 GC: sweep should delete the previously marked endpoint (healthyID).
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.False(t, mgr.EndpointExists(healthyID), "endpoint should be deleted after round 4 GC")
	require.Empty(t, mgr.GetEndpoints(), "no endpoints should exist after round 4 GC")
}

// TestMarkAndSweepEndpointIDRecover verifies that if an endpoint is marked as a GC
// candidate in one round but recovers (becomes healthy) before the next sweep,
// it will not be deleted and will be removed from markedEndpoints.
func TestMarkAndSweepEndpointIDRecover(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	mgr.checkHealth = fakeCheck
	mgr.deleteEndpoint = endpointDeleteFunc(mgr.waitEndpointRemoved)

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create an unhealthy endpoint (even ID, fakeCheck returns error for even IDs)
	unhealthyID := uint16(256)
	model := newTestEndpointModel(int(unhealthyID), endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(makeTestEndpointParams(logger, s.repo), nil, &endpoint.FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)
	ep.Start(unhealthyID)
	t.Cleanup(ep.Stop)
	err = mgr.expose(ep)
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), 1)

	// Round 1 GC: sweep is empty (nothing to delete), mark tags the unhealthy endpoint.
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.True(t, mgr.EndpointExists(unhealthyID), "endpoint should still exist after round 1 GC")
	require.Len(t, mgr.GetEndpoints(), 1)

	// Verify that unhealthyID is now marked in markedEndpoints after round 1.
	require.True(t, mgr.isMarkedEndpoint(unhealthyID), "unhealthyID should be marked in markedEndpoints after round 1 GC")

	// Simulate endpoint recovery: switch checkHealth to fakeCheckHealthy so the
	// endpoint is now considered healthy before the next sweep executes.
	mgr.checkHealth = fakeCheckHealthy

	// Round 2 GC: sweep would normally delete the marked endpoint, but since the
	// endpoint is now healthy, it should NOT be deleted. Instead, it should be
	// removed from markedEndpoints because it passes the health check.
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.True(t, mgr.EndpointExists(unhealthyID), "recovered endpoint should NOT be deleted in round 2 GC")
	require.Len(t, mgr.GetEndpoints(), 1)

	// Verify that unhealthyID is no longer in markedEndpoints after recovery.
	require.False(t, mgr.isMarkedEndpoint(unhealthyID), "recovered endpoint should be removed from markedEndpoints after round 2 GC")
}

func newTestEndpointModel(id int, state endpoint.State) *models.EndpointChangeRequest {
	return &models.EndpointChangeRequest{
		ID:    int64(id),
		State: ptr.To(models.EndpointState(state)),
		Properties: map[string]any{
			endpointtypes.PropertyFakeEndpoint: true,
		},
	}
}
