// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/compute"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

// This test fuzzes the incremental update engine from an end-to-end perspective
// to ensure we don't ever miss an incremental update.
//
// It works by simulating a "churning" IPcache that is constantly allocating new identities.
// There is a single policy that -- funnily enough -- selects all of the new identities.
// We then continuously simulate endpoint regeneration and ensure the computed policy contains
// all the generated identities.
//
// By default, we test 1000 identities, which should take less than 10 seconds. If this test fails,
// please bump the factor to something massive and start debugging :-).
func TestIncrementalUpdatesDuringPolicyGeneration(t *testing.T) {
	const testfactor = 1000 // bump this to stress-test

	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	idcache := make(identity.IdentityMap, testfactor)
	logger := hivetest.Logger(t)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	idManager := identitymanager.NewIDManager(hivetest.Logger(t))
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache().ToOld(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := testcompute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", "TestIncrementalUpdatesDuringPolicyGeneration", repo, idManager)

	addIdentity := func(labelKeys ...string) *identity.Identity {
		t.Helper()
		lbls := labels.Labels{}
		for _, labelKey := range labelKeys {
			lbls[labelKey] = labels.NewLabel("k8s:"+labelKey, "", "")
		}
		id, _, err := fakeAllocator.AllocateIdentity(context.Background(), lbls, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		// t.Logf("allocated label %s id %d", labelKeys, id.ID) // commented out for speed

		wg := &sync.WaitGroup{}
		repo.GetSelectorCache().UpdateIdentities(identity.IdentityMapOld{
			id.ID: id.LabelArray,
		}, nil, wg)
		wg.Wait()
		return id
	}

	podID := addIdentity("pod")

	ep := Endpoint{
		policyRepo:       repo,
		policyFetcher:    polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(hivetest.Logger(t), repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: podID,
		identityManager:  idManager,
	}
	ep.UpdateLogger(nil)

	idManager.Add(podID)

	podSelectLabel := labels.ParseSelectLabel("pod")
	egressSelectLabel := labels.ParseSelectLabel("peer")

	// Create a rule for our pod that selects all peer identities
	egressDenyRule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(podSelectLabel),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(egressSelectLabel),
					},
				},
				ToPorts: []api.PortDenyRule{
					{
						Ports: []api.PortProtocol{
							{
								Port:     "80",
								Protocol: "TCP",
							},
						},
					},
				},
			},
		},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, "egressDenyRule", labels.LabelSourceAny),
		},
	}

	_, rev := repo.MustAddList(api.Rules{egressDenyRule})
	computePolicyForEPAndWait(t, &ep, polComputer, rev)

	// Track all IDs we allocate so we can validate later that we never miss any
	checkMutex := lock.Mutex{}
	allocatedIDs := make(sets.Set[identity.NumericIdentity], testfactor)
	done := atomic.Bool{}

	// simulate ipcache churn: continuously allocate IDs and push them to the policy engine.
	go func() {
		for i := range testfactor {
			if i%100 == 0 {
				t.Log(i)
			}
			id := addIdentity("peer", fmt.Sprintf("peer%d", i))

			// note: we could stop checking here and the last ID would be missing from allocatedIDs
			// so we will have to handle the case where we select one more ID than is in allocatedIDs
			checkMutex.Lock()
			allocatedIDs.Insert(id.ID)
			checkMutex.Unlock()

		}
		done.Store(true)
	}()

	stats := new(regenerationStatistics)
	datapathRegenCtxt := new(datapathRegenerationContext)
	datapathRegenCtxt.policyRevisionToWaitFor = rev
	// Continuously compute policy for the pod and ensure we never missed an incremental update.
	for {
		t.Log("Calculating policy...")
		ep.forcePolicyCompute = true
		err := ep.regeneratePolicy(stats, datapathRegenCtxt)
		assert.NoError(t, err)
		res := datapathRegenCtxt.policyResult

		// Sleep a random amount, so we accumulate some changes
		// This does not slow down the test, since we always generate testFactor identities.
		time.Sleep(time.Duration(rand.IntN(10)) * time.Millisecond)

		// Now, check that all the expected entries are there
		checkMutex.Lock()
		t.Log("Checking policy...")

		// Apply any pending incremental changes
		// This mirrors the existing code, where we consume map changes
		// while holding the endpoint lock
		closer, _ := res.endpointPolicy.ConsumeMapChanges()
		closer()

		haveIDs := make(sets.Set[identity.NumericIdentity], testfactor)
		for k := range res.endpointPolicy.Entries() {
			haveIDs.Insert(k.Identity)
		}

		// It is okay if we have *more* IDs than allocatedIDs, since we may have propagated
		// an ID change through the policy system but not yet added to the extra list we're
		// keeping in this test.
		//
		// It is confusing, but this assertion checks that allocatedIDs is a subset of haveIDs,
		// not the other way around.
		assert.Subset(t, haveIDs, allocatedIDs, "stress-testing the incremental update system failed! DO NOT just retest, there is a race condition!")

		checkMutex.Unlock()

		if done.Load() {
			break
		}
	}
}

func computePolicyForEPAndWait(t *testing.T, ep *Endpoint, fetcher compute.PolicyRecomputer, rev uint64) {
	t.Helper()

	computedPolicyCh, err := fetcher.RecomputeIdentityPolicy(ep.SecurityIdentity, rev)
	assert.NoError(t, err)
	assert.NotNil(t, computedPolicyCh)
	<-computedPolicyCh
}

type policyTestFixture struct {
	repo        *policy.Repository
	polComputer compute.PolicyRecomputer
	idManager   identitymanager.IDManager
	podID       *identity.Identity
}

func newPolicyTestFixture(t *testing.T) *policyTestFixture {
	t.Helper()

	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	t.Cleanup(func() { policy.SetPolicyEnabled(pe) })

	logger := hivetest.Logger(t)
	idcache := make(identity.IdentityMap)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache().ToOld(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := testcompute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", t.Name(), repo, idManager)

	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMapOld{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

	idManager.Add(podID)

	return &policyTestFixture{
		repo:        repo,
		polComputer: polComputer,
		idManager:   idManager,
		podID:       podID,
	}
}

// TestStaleStatedbEntry covers the case where identity refcount drops to 0.
// The DELETE handler must clean up the statedb entry even though the identity
// is already gone from idmanager.
func TestStaleStatedbEntry(t *testing.T) {
	f := newPolicyTestFixture(t)
	logger := hivetest.Logger(t)

	epA := Endpoint{
		policyRepo:       f.repo,
		policyFetcher:    f.polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, f.repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: f.podID,
		identityManager:  f.idManager,
	}
	epA.UpdateLogger(nil)

	podSelectLabel := labels.ParseSelectLabel("pod")
	egressSelectLabel := labels.ParseSelectLabel("peer")
	rule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(podSelectLabel),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(egressSelectLabel),
					},
				},
				ToPorts: []api.PortDenyRule{
					{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: "TCP"},
						},
					},
				},
			},
		},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, "testRule", labels.LabelSourceAny),
		},
	}
	_, rev := f.repo.MustAddList(api.Rules{rule})

	require.Eventually(t, func() bool {
		_, _, _, found := f.polComputer.GetIdentityPolicyByNumericIdentity(f.podID.ID)
		return found
	}, 5*time.Second, 10*time.Millisecond)

	computePolicyForEPAndWait(t, &epA, f.polComputer, rev)

	statsA := new(regenerationStatistics)
	regenCtxA := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err := epA.regeneratePolicy(statsA, regenCtxA)
	require.NoError(t, err)
	require.NotNil(t, regenCtxA.policyResult.endpointPolicy)
	epA.desiredPolicy = regenCtxA.policyResult.endpointPolicy

	epA.desiredPolicy.Ready()
	epA.desiredPolicy.Detach(logger)
	f.idManager.Remove(f.podID)

	_, _, _, found := f.polComputer.GetIdentityPolicyByNumericIdentity(f.podID.ID)
	require.False(t, found)

	f.idManager.Add(f.podID)

	epB := Endpoint{
		policyRepo:       f.repo,
		policyFetcher:    f.polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, f.repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: f.podID,
		identityManager:  f.idManager,
	}
	epB.UpdateLogger(nil)

	computePolicyForEPAndWait(t, &epB, f.polComputer, rev)

	statsB := new(regenerationStatistics)
	regenCtxB := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epB.regeneratePolicy(statsB, regenCtxB)
	require.NoError(t, err)
	require.NotNil(t, regenCtxB.policyResult.endpointPolicy)

	regenCtxB.policyResult.endpointPolicy.Ready()
	regenCtxB.policyResult.endpointPolicy.Detach(logger)
	f.idManager.Remove(f.podID)
}

// TestSupersedeDuringRegen covers the race where a concurrent
// computeSelectorPolicy adds a uniquely-labelled rule and returns the resulting
// live SelectorPolicy for the fixture's identity.
func computeSelectorPolicy(t *testing.T, f *policyTestFixture, name string) policy.SelectorPolicy {
	t.Helper()
	rule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("pod")),
		EgressDeny: []api.EgressDenyRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("peer"))},
			},
			ToPorts: []api.PortDenyRule{{Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}}}},
		}},
		Labels: labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceAny)},
	}
	_, rev := f.repo.MustAddList(api.Rules{rule})
	done, err := f.polComputer.RecomputeIdentityPolicy(f.podID, rev)
	require.NoError(t, err)
	<-done
	res, _, _, found := f.polComputer.GetIdentityPolicyByIdentity(f.podID)
	require.True(t, found)
	require.NotNil(t, res.NewPolicy)
	return res.NewPolicy
}

// supersedeFetcher serves a detached policy on the first read, then a live one.
// Closing the first read's watch channel wakes the wait loop deterministically.
type supersedeFetcher struct {
	compute.PolicyRecomputer
	results []compute.Result
	watch   chan struct{}
}

func (f *supersedeFetcher) GetIdentityPolicyByIdentity(*identity.Identity) (compute.Result, statedb.Revision, <-chan struct{}, bool) {
	res, watch := f.results[0], f.watch
	if len(f.results) > 1 {
		f.results = f.results[1:]
		close(watch) // wake the wait loop so it re-reads the replacement
		f.watch = make(chan struct{})
	}
	return res, 0, watch, true
}

// waitForPolicyComputationResult must skip a superseded policy and wait for the
// replacement instead of failing.
func TestWaitSkipsSupersededPolicy(t *testing.T) {
	f := newPolicyTestFixture(t)
	const rev = 1

	detached := computeSelectorPolicy(t, f, "detached")
	detached.Supersede()
	require.False(t, detached.AddHold())

	live := computeSelectorPolicy(t, f, "live")

	fetcher := &supersedeFetcher{
		PolicyRecomputer: f.polComputer,
		results: []compute.Result{
			{NewPolicy: detached, Revision: rev},
			{NewPolicy: live, Revision: rev},
		},
		watch: make(chan struct{}),
	}

	ep := Endpoint{policyFetcher: fetcher, SecurityIdentity: f.podID}
	ep.UpdateLogger(nil)

	res, err := ep.waitForPolicyComputationResult(
		&datapathRegenerationContext{policyRevisionToWaitFor: rev}, f.podID)
	require.NoError(t, err)
	require.Same(t, live, res.NewPolicy)

	live.ReleaseHold()
}

// A duplicate regeneration trigger is skipped, but the queued regeneration must
// still wait for the highest revision that was skipped.
func TestSkippedPolicyRevision(t *testing.T) {
	const (
		rev1 = 198
		rev2 = 199
		rev3 = 200
	)

	newEP := func() *Endpoint {
		ep := &Endpoint{status: NewEndpointStatus()}
		ep.UpdateLogger(nil)
		return ep
	}

	// skip triggers a regeneration while one is already queued and reports
	// whether it was skipped.
	skip := func(ep *Endpoint, rev uint64) bool {
		ep.unconditionalLock()
		defer ep.unlock()
		return !ep.setRegenerateStateLocked(&regeneration.ExternalRegenerationMetadata{
			Reason:                  regeneration.ReasonPolicyUpdate,
			RegenerationLevel:       regeneration.RegenerateWithoutDatapath,
			PolicyRevisionToWaitFor: rev,
		})
	}

	consume := func(ep *Endpoint, ctx *datapathRegenerationContext) {
		ep.unconditionalLock()
		defer ep.unlock()
		ep.consumeSkippedPolicyRevision(ctx)
	}

	t.Run("skip captures highest revision and regen consumes it", func(t *testing.T) {
		ep := newEP()
		ep.state = StateWaitingToRegenerate

		require.True(t, skip(ep, rev2))
		require.Equal(t, uint64(rev2), ep.skippedPolicyRevision)

		// A lower revision must not lower it. A higher one wins.
		require.True(t, skip(ep, rev1))
		require.Equal(t, uint64(rev2), ep.skippedPolicyRevision)
		require.True(t, skip(ep, rev3))
		require.Equal(t, uint64(rev3), ep.skippedPolicyRevision)

		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev1}
		consume(ep, ctx)
		require.Equal(t, uint64(rev3), ctx.policyRevisionToWaitFor)
		require.Zero(t, ep.skippedPolicyRevision)
	})

	t.Run("consume does not lower a higher ctx revision", func(t *testing.T) {
		ep := newEP()
		ep.state = StateWaitingToRegenerate
		require.True(t, skip(ep, rev2))

		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev3}
		consume(ep, ctx)
		require.Equal(t, uint64(rev3), ctx.policyRevisionToWaitFor)
	})

	t.Run("fresh trigger does not set skippedPolicyRevision", func(t *testing.T) {
		ep := newEP()
		ep.state = StateReady // not already queued, so the trigger is not a duplicate
		require.False(t, skip(ep, rev2))
		require.Zero(t, ep.skippedPolicyRevision)
	})
}
