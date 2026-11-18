// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"iter"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/completion"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/policymap"
	fakepolicymap "github.com/cilium/cilium/pkg/maps/policymap/fake"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/revert"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

// batchTestPolicyMapFactory records the syncs of endpoints to the shared policy map.
type batchTestPolicyMapFactory struct {
	fakepolicymap.Factory

	mu lock.Mutex
	// syncs are the endpoints synced by SyncEndpointOverlay.
	syncs []uint16
	// batches are the endpoints synced by each SyncEndpointOverlays.
	batches  [][]uint16
	prepared map[*policymap.EndpointOverlay]uint16
	// errs are the sync errors of the endpoints.
	errs map[uint16]error
}

func newBatchTestPolicyMapFactory() *batchTestPolicyMapFactory {
	return &batchTestPolicyMapFactory{
		prepared: make(map[*policymap.EndpointOverlay]uint16),
		errs:     make(map[uint16]error),
	}
}

func (f *batchTestPolicyMapFactory) SharedPolicyEnabled() bool { return true }

func (f *batchTestPolicyMapFactory) SyncEndpointOverlay(epID uint16, _ iter.Seq2[policytypes.Key, policytypes.MapStateEntry]) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs = append(f.syncs, epID)
	return f.errs[epID]
}

func (f *batchTestPolicyMapFactory) PrepareEndpointOverlay(epID uint16, _ iter.Seq2[policytypes.Key, policytypes.MapStateEntry]) *policymap.EndpointOverlay {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := new(policymap.EndpointOverlay)
	f.prepared[o] = epID
	return o
}

func (f *batchTestPolicyMapFactory) SyncEndpointOverlays(overlays []*policymap.EndpointOverlay) []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	errs := make([]error, len(overlays))
	epIDs := make([]uint16, len(overlays))
	for i, o := range overlays {
		epIDs[i] = f.prepared[o]
		errs[i] = f.errs[epIDs[i]]
	}
	f.batches = append(f.batches, epIDs)
	return errs
}

func (f *batchTestPolicyMapFactory) setErr(epID uint16, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[epID] = err
}

func (f *batchTestPolicyMapFactory) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs, f.batches = nil, nil
}

// newSharedPolicyTestEndpoints creates endpoints whose policy allows egress to identities
// with the "peer" label, and whose policy is synced to the shared policy map. It returns
// them and a function that adds a peer identity.
func newSharedPolicyTestEndpoints(t *testing.T, factory policymap.Factory, epIDs ...uint16) ([]*Endpoint, func(name string)) {
	t.Helper()

	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	t.Cleanup(func() { policy.SetPolicyEnabled(pe) })

	logger := hivetest.Logger(t)
	fakeAllocator := testidentity.NewMockIdentityAllocator(nil)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := testcompute.InstantiateCellForTesting(t, logger, "endpoint-shared_policy_test", t.Name(), repo, idManager)

	addIdentity := func(labelKeys ...string) *identity.Identity {
		lbls := labels.Labels{}
		for _, labelKey := range labelKeys {
			lbls[labelKey] = labels.NewLabel("k8s:"+labelKey, "", "")
		}
		id, _, err := fakeAllocator.AllocateIdentity(context.Background(), lbls, false, 0)
		require.NoError(t, err)
		wg := &sync.WaitGroup{}
		repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{id.ID: id.Labels}, nil, wg)
		wg.Wait()
		return id
	}

	podID := addIdentity("pod")
	idManager.Add(podID)

	_, rev := repo.MustAddList(api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("pod")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("peer"))},
			},
		}},
		Labels: labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, "allowPeers", labels.LabelSourceAny)},
	}})

	var eps []*Endpoint
	for _, epID := range epIDs {
		p := createEndpointParams(t, &fakeendpoint.FakeOrchestrator{}, repo, polComputer)
		p.IdentityManager = idManager
		p.PolicyMapFactory = factory
		ep := createEndpoint(p, nil, nil, epID, "", nil)
		t.Cleanup(ep.aliveCancel)
		ep.SecurityIdentity = podID
		ep.UpdateLogger(nil)

		computePolicyForEPAndWait(t, ep, polComputer, rev)
		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
		require.NoError(t, ep.regeneratePolicy(new(regenerationStatistics), ctx))
		require.NoError(t, ep.lockAlive())
		require.NoError(t, ep.setDesiredPolicy(ctx))
		require.True(t, ep.desiredPolicy.IsValid())
		// The endpoint's regeneration syncs its new policy.
		require.NoError(t, ep.syncSharedPolicyLocked())
		ep.unlock()
		eps = append(eps, ep)
	}
	return eps, func(name string) { addIdentity("peer", name) }
}

// applyBatched applies the incremental policy changes of the endpoints and syncs them to the
// shared policy map together, like the endpoint manager's UpdatePolicyMaps, and returns the
// result of each endpoint.
func applyBatched(eps []*Endpoint) map[uint16]error {
	var (
		mu      lock.Mutex
		results = make(map[uint16]error)
		batch   SharedPolicyBatch
	)
	done := func(e *Endpoint, err error, revertible revert.Revertible) {
		if revertible != nil {
			revertible.Finalize()
		}
		mu.Lock()
		defer mu.Unlock()
		results[e.ID] = err
	}
	cmp := completion.NewWaitGroup(context.Background())
	for _, ep := range eps {
		err, revertible := ep.ApplyPolicyMapChangesBatched(cmp, &batch)
		done(ep, err, revertible)
	}
	batch.Sync(done)
	return results
}

// TestSharedPolicyIncrementalUpdates checks that incremental policy changes are synced to the
// shared policy map in one batch for all endpoints they change, that endpoints they do not
// change are not synced, and that a failed sync is retried by the next update.
func TestSharedPolicyIncrementalUpdates(t *testing.T) {
	factory := newBatchTestPolicyMapFactory()
	eps, addPeer := newSharedPolicyTestEndpoints(t, factory, 1, 2)
	factory.reset()

	// Nothing changed since the endpoints were regenerated.
	require.Equal(t, map[uint16]error{1: nil, 2: nil}, applyBatched(eps))
	require.Empty(t, factory.syncs)
	require.Empty(t, factory.batches)

	// A new peer changes the policy of both endpoints.
	addPeer("peer1")
	require.Equal(t, map[uint16]error{1: nil, 2: nil}, applyBatched(eps))
	require.Empty(t, factory.syncs, "the endpoints are not synced one by one")
	require.Len(t, factory.batches, 1)
	require.ElementsMatch(t, []uint16{1, 2}, factory.batches[0])

	factory.reset()
	require.Equal(t, map[uint16]error{1: nil, 2: nil}, applyBatched(eps))
	require.Empty(t, factory.batches)

	// A failed sync is retried by the next update, even if nothing changed since.
	errSync := errors.New("sync failed")
	factory.setErr(1, errSync)
	addPeer("peer2")
	results := applyBatched(eps)
	require.ErrorIs(t, results[1], errSync)
	require.NoError(t, results[2])

	factory.reset()
	factory.setErr(1, nil)
	require.Equal(t, map[uint16]error{1: nil, 2: nil}, applyBatched(eps))
	require.Equal(t, [][]uint16{{1}}, factory.batches)

	// ApplyPolicyMapChanges syncs right away.
	factory.reset()
	addPeer("peer3")
	for _, ep := range eps {
		err, revertible := ep.ApplyPolicyMapChanges(completion.NewWaitGroup(context.Background()))
		require.NoError(t, err)
		if revertible != nil {
			revertible.Finalize()
		}
	}
	require.ElementsMatch(t, []uint16{1, 2}, factory.syncs)
	require.Empty(t, factory.batches)
}

// TestSharedPolicyBatchSuperseded checks that the result of a batched sync is ignored when a
// later sync of the endpoint, e.g. by its regeneration, replaced it, and that a batched sync
// of a desired policy that changed since does not count as synced.
func TestSharedPolicyBatchSuperseded(t *testing.T) {
	factory := newBatchTestPolicyMapFactory()
	eps, addPeer := newSharedPolicyTestEndpoints(t, factory, 1)
	ep := eps[0]
	cmp := completion.NewWaitGroup(context.Background())

	addPeer("peer1")
	var batch SharedPolicyBatch
	err, revertible := ep.ApplyPolicyMapChangesBatched(cmp, &batch)
	require.NoError(t, err)
	require.Nil(t, revertible, "the batch reports the result")

	// The endpoint is synced again before the batch syncs it.
	require.NoError(t, ep.lockAlive())
	require.NoError(t, ep.syncSharedPolicyLocked())
	ep.unlock()

	factory.setErr(1, errors.New("superseded sync failed"))
	var results []error
	batch.Sync(func(_ *Endpoint, err error, _ revert.Revertible) { results = append(results, err) })
	require.Equal(t, []error{nil}, results)
	require.Same(t, ep.desiredPolicy, ep.sharedPolicySynced, "the later sync's result is kept")

	// The desired policy changes after the batched sync is prepared.
	factory.setErr(1, nil)
	addPeer("peer2")
	err, _ = ep.ApplyPolicyMapChangesBatched(cmp, &batch)
	require.NoError(t, err)
	require.NoError(t, ep.lockAlive())
	ep.sharedPolicyChanges++
	ep.unlock()
	results = nil
	batch.Sync(func(_ *Endpoint, err error, _ revert.Revertible) { results = append(results, err) })
	require.Equal(t, []error{nil}, results)
	require.Nil(t, ep.sharedPolicySynced, "the next update syncs the endpoint again")
}
