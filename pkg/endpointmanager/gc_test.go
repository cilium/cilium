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
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
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
		ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
			EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
			NamedPortsGetter: testipcache.NewMockIPCache(),
			Allocator:        testidentity.NewMockIdentityAllocator(nil),
			CTMapGC:          ctmap.NewFakeGCRunner(),
			WgConfig:         &fakeTypes.WireguardConfig{},
			IPSecConfig:      fakeTypes.IPsecConfig{},
			Logger:           logger,
			IdentityManager:  identitymanager.NewIDManager(logger),
			PolicyRepo:       s.repo,
		}, nil, &endpoint.FakeEndpointProxy{}, model, nil)
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
	ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
		EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
		NamedPortsGetter: testipcache.NewMockIPCache(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
		CTMapGC:          ctmap.NewFakeGCRunner(),
		WgConfig:         &fakeTypes.WireguardConfig{},
		IPSecConfig:      fakeTypes.IPsecConfig{},
		Logger:           logger,
		IdentityManager:  identitymanager.NewIDManager(logger),
		PolicyRepo:       s.repo,
	}, nil, &endpoint.FakeEndpointProxy{}, model, nil)
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
	mgr.mutex.RLock()
	markedLen := len(mgr.markedEndpoints)
	mgr.mutex.RUnlock()
	require.Equal(t, 0, markedLen, "markedEndpoints should be empty after endpoint is deleted")

	// Simulate endpoint ID reuse: create a new healthy endpoint.
	// Since fakeCheck marks even IDs as unhealthy, we use an odd ID
	// to simulate a healthy endpoint.
	healthyID := uint16(testEPID)
	model2 := newTestEndpointModel(int(healthyID), endpoint.StateReady)
	ep2, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
		EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
		NamedPortsGetter: testipcache.NewMockIPCache(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
		CTMapGC:          ctmap.NewFakeGCRunner(),
		WgConfig:         &fakeTypes.WireguardConfig{},
		IPSecConfig:      fakeTypes.IPsecConfig{},
		Logger:           logger,
		IdentityManager:  identitymanager.NewIDManager(logger),
		PolicyRepo:       s.repo,
	}, nil, &endpoint.FakeEndpointProxy{}, model2, nil)
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
}

// TestMarkAndSweepEndpointIDReuse verifies that when an endpoint ID is reused between
// mark and sweep phases, the garbage collection correctly avoids deleting the new endpoint.
func TestMarkAndSweepEndpointIDReuse(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	mgr.checkHealth = fakeCheck
	mgr.deleteEndpoint = endpointDeleteFunc(mgr.waitEndpointRemoved)

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create an unhealthy endpoint with ID 123 (even ID, will be marked for GC)
	reusedID := uint16(123)
	model1 := newTestEndpointModel(int(reusedID), endpoint.StateReady)
	ep1, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
		EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
		NamedPortsGetter: testipcache.NewMockIPCache(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
		CTMapGC:          ctmap.NewFakeGCRunner(),
		WgConfig:         &fakeTypes.WireguardConfig{},
		IPSecConfig:      fakeTypes.IPsecConfig{},
		Logger:           logger,
		IdentityManager:  identitymanager.NewIDManager(logger),
		PolicyRepo:       s.repo,
	}, nil, &endpoint.FakeEndpointProxy{}, model1, nil)
	require.NoError(t, err)
	ep1.Start(reusedID)
	t.Cleanup(ep1.Stop)
	err = mgr.expose(ep1)
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), 1)

	// Round 1 GC: sweep is empty, mark tags the unhealthy endpoint 123
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.True(t, mgr.EndpointExists(reusedID), "endpoint should still exist after round 1 GC")
	require.Len(t, mgr.GetEndpoints(), 1)

	// Simulate the scenario: endpoint 123 is deleted and a new endpoint reuses the same ID
	// First, remove the original endpoint
	errs := mgr.RemoveEndpoint(ep1, endpoint.DeleteConfig{NoIPRelease: false})
	if len(errs) > 0 {
		for _, err := range errs {
			require.NoError(t, err, "should be able to remove endpoint without error")
		}
	}
	require.False(t, mgr.EndpointExists(reusedID), "original endpoint should be deleted")
	require.Empty(t, mgr.GetEndpoints(), "no endpoints should exist after deletion")

	// Make checkHealth return healthy
	mgr.checkHealth = fakeCheckHealthy
	// Create a new endpoint with the same ID 123, but this time it whill be healthy
	healthyReusedID := uint16(123)
	model2 := newTestEndpointModel(int(healthyReusedID), endpoint.StateReady)
	ep2, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
		EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
		NamedPortsGetter: testipcache.NewMockIPCache(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
		CTMapGC:          ctmap.NewFakeGCRunner(),
		WgConfig:         &fakeTypes.WireguardConfig{},
		IPSecConfig:      fakeTypes.IPsecConfig{},
		Logger:           logger,
		IdentityManager:  identitymanager.NewIDManager(logger),
		PolicyRepo:       s.repo,
	}, nil, &endpoint.FakeEndpointProxy{}, model2, nil)
	require.NoError(t, err)
	ep2.Start(healthyReusedID)
	t.Cleanup(ep2.Stop)
	err = mgr.expose(ep2)
	require.NoError(t, err)
	require.Len(t, mgr.GetEndpoints(), 1)
	require.True(t, mgr.EndpointExists(healthyReusedID), "new endpoint should exist")

	// Round 2 GC: sweep should use the markedEndpoints from round 1 (which contains ID 123)
	// but due to the stricter checking in sweepEndpoints, it should detect that this is a
	// different endpoint and avoid deleting it.
	err = mgr.markAndSweep(ctx)
	require.NoError(t, err)
	require.True(t, mgr.EndpointExists(healthyReusedID), "new endpoint should not be deleted due to ID reuse protection")
	require.Len(t, mgr.GetEndpoints(), 1, "endpoint count should remain 1")

	// Verify that the endpoint is indeed healthy (passes health check)
	err = mgr.checkHealth(ep2)
	require.NoError(t, err, "new endpoint should pass health check")
}

func newTestEndpointModel(id int, state endpoint.State) *models.EndpointChangeRequest {
	return &models.EndpointChangeRequest{
		ID:    int64(id),
		State: ptr.To(models.EndpointState(state)),
		Properties: map[string]any{
			endpoint.PropertyFakeEndpoint: true,
		},
	}
}
