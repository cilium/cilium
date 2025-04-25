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

func TestMarkAndSweep(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	// Open-code WithPeriodicGC() to avoid running the controller
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
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
		ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
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

func newTestEndpointModel(id int, state endpoint.State) *models.EndpointChangeRequest {
	return &models.EndpointChangeRequest{
		ID:    int64(id),
		State: ptr.To(models.EndpointState(state)),
		Properties: map[string]interface{}{
			endpoint.PropertyFakeEndpoint: true,
		},
	}
}
