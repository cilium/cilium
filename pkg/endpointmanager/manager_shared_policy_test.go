// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"iter"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	fakepolicymap "github.com/cilium/cilium/pkg/maps/policymap/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

// sharedPolicyRecorder records the syncs of endpoints to the shared policy map.
type sharedPolicyRecorder struct {
	fakepolicymap.Factory

	mu       lock.Mutex
	syncs    []uint16
	batches  [][]uint16
	prepared map[*policymap.EndpointOverlay]uint16
}

func (f *sharedPolicyRecorder) SharedPolicyEnabled() bool { return true }

func (f *sharedPolicyRecorder) SyncEndpointOverlay(epID uint16, _ iter.Seq2[policytypes.Key, policytypes.MapStateEntry]) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs = append(f.syncs, epID)
	return nil
}

func (f *sharedPolicyRecorder) PrepareEndpointOverlay(epID uint16, _ iter.Seq2[policytypes.Key, policytypes.MapStateEntry]) *policymap.EndpointOverlay {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := new(policymap.EndpointOverlay)
	f.prepared[o] = epID
	return o
}

func (f *sharedPolicyRecorder) SyncEndpointOverlays(overlays []*policymap.EndpointOverlay) []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	epIDs := make([]uint16, len(overlays))
	for i, o := range overlays {
		epIDs[i] = f.prepared[o]
	}
	f.batches = append(f.batches, epIDs)
	return make([]error, len(overlays))
}

func (f *sharedPolicyRecorder) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs, f.batches = nil, nil
}

// TestUpdatePolicyMapsSharedPolicyBatch checks that UpdatePolicyMaps syncs the endpoints whose
// policy changed to the shared policy map in one batch, and does not sync the others.
func TestUpdatePolicyMapsSharedPolicyBatch(t *testing.T) {
	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())
	fetcher := testcompute.InstantiateCellForTesting(t, logger, "endpointmanager", "shared policy batch", repo, idmgr)
	oldPolicyMode := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)
	t.Cleanup(func() { policy.SetPolicyEnabled(oldPolicyMode) })

	// Endpoints with the "bar" label allow ingress from identities with the "peer" label.
	repo.MustAddList(api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("peer"))},
			},
		}},
	}})

	factory := &sharedPolicyRecorder{prepared: make(map[*policymap.EndpointOverlay]uint16)}
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	var eps []*endpoint.Endpoint
	for i, addr := range []string{"10.0.4.1", "10.0.4.2"} {
		model := newTestEndpointModel(501+i, endpoint.StateWaitingForIdentity)
		ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
			Logger:           logger,
			EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
			Orchestrator:     &fakeendpoint.FakeOrchestrator{},
			PolicyRepo:       repo,
			PolicyFetcher:    fetcher,
			PolicyMapFactory: factory,
			IdentityManager:  idmgr,
			IPSecConfig:      fakeipsec.Config{},
			WgConfig:         &fakewireguard.Config{},
			CTMapGC:          ctmap.NewFakeGCRunner(),
			Allocator:        testidentity.NewMockIdentityAllocator(nil),
			KVStoreSynchronizer: ipcache.NewIPIdentitySynchronizer(
				logger,
				kvstore.SetupDummy(t, kvstore.DisabledBackendName),
			),
		}, nil, nil, model, nil)
		require.NoError(t, err)
		ep.Start(uint16(model.ID))
		t.Cleanup(ep.Stop)
		ep.IPv4 = netip.MustParseAddr(addr)
		ep.SetIdentity(identity.NewIdentityFromLabelArray(identity.NumericIdentity(1501+i), labels.ParseLabelArray("k8s:bar")))
		require.NoError(t, mgr.expose(ep))
		require.True(t, <-ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
			Reason:            regeneration.ReasonPolicyUpdate,
			RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		}))
		eps = append(eps, ep)
	}
	factory.reset()

	// The mock build queue skips the regeneration after the initial policy computation, so
	// the policies are not in the shared policy map yet. The first update syncs them.
	require.NoError(t, mgr.UpdatePolicyMaps(t.Context()))
	require.Empty(t, factory.syncs, "the endpoints are not synced one by one")
	require.Len(t, factory.batches, 1)
	require.ElementsMatch(t, []uint16{eps[0].ID, eps[1].ID}, factory.batches[0])

	// Nothing changed since.
	factory.reset()
	require.NoError(t, mgr.UpdatePolicyMaps(t.Context()))
	require.Empty(t, factory.syncs)
	require.Empty(t, factory.batches)

	// A new peer changes the policy of both endpoints.
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{
		identity.NumericIdentity(1600): labels.NewLabelsFromModel([]string{"k8s:peer"}),
	}, nil, wg)
	wg.Wait()
	factory.reset()
	require.NoError(t, mgr.UpdatePolicyMaps(t.Context()))
	require.Empty(t, factory.syncs, "the endpoints are not synced one by one")
	require.Len(t, factory.batches, 1)
	require.ElementsMatch(t, []uint16{eps[0].ID, eps[1].ID}, factory.batches[0])

	factory.reset()
	require.NoError(t, mgr.UpdatePolicyMaps(t.Context()))
	require.Empty(t, factory.syncs)
	require.Empty(t, factory.batches)
}
