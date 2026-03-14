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
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := compute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", "TestIncrementalUpdatesDuringPolicyGeneration", repo, idManager)

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
		repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{
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

// TestRemoveUserCausesRegenFailure reproduces the race condition from the
// "Cilium Cluster Mesh upgrade" CI failure (run 22766154716) where:
//
//  1. Endpoint A with identity X has policy P computed (stored in statedb)
//  2. Endpoint A regenerates: regeneratePolicy() → AddHold → DistillPolicy → user registered
//  3. Endpoint B with same identity arrives (identityManager refCount 1→2)
//  4. Endpoint A starts leaving: leaveLocked:1289 → desiredPolicy.Detach() → removeUser → P DETACHED
//  5. Endpoint A finishes leaving: leaveLocked:1316 → identityManager.Remove → refCount 2→1 (no cleanup)
//  6. Endpoint B calls regeneratePolicy(): reads detached P from statedb → AddHold fails
//     → "selector policy was detached, aborting regeneration" (appeared 1,038x in CI sysdump)
//
// Without fix: test FAILS at step 6 — regeneratePolicy returns the detached error
// With fix: test PASSES — removeUser keeps P idle, B's AddHold succeeds
func TestRemoveUserCausesRegenFailure(t *testing.T) {
	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	logger := hivetest.Logger(t)
	idcache := make(identity.IdentityMap)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := compute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", "TestRemoveUserCausesRegenFailure", repo, idManager)

	// Create identity for our pod
	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

	// --- Step 1: Endpoint A arrives ---
	idManager.Add(podID)

	// Create endpoint A with real policy infrastructure
	epA := Endpoint{
		policyRepo:       repo,
		policyFetcher:    polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: podID,
		identityManager:  idManager,
	}
	epA.UpdateLogger(nil)

	// Add a policy rule so there's actual policy to compute
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
	_, rev := repo.MustAddList(api.Rules{rule})
	computePolicyForEPAndWait(t, &epA, polComputer, rev)

	// --- Step 2: Endpoint A regenerates (real regeneratePolicy call) ---
	statsA := new(regenerationStatistics)
	regenCtxA := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epA.regeneratePolicy(statsA, regenCtxA)
	require.NoError(t, err, "endpoint A regeneration must succeed")
	require.NotNil(t, regenCtxA.policyResult.endpointPolicy)

	// Update desiredPolicy to the computed EndpointPolicy (what setDesiredPolicy does)
	// so that Detach() will call removeUser on the correct selectorPolicy
	epA.desiredPolicy = regenCtxA.policyResult.endpointPolicy

	// --- Step 3: Endpoint B arrives BEFORE A finishes leaving ---
	// identityManager.Add → refCount 1→2, no observer notification (already present)
	idManager.Add(podID)

	// --- Step 4: Endpoint A starts leaving (leaveLocked line 1289) ---
	// Production: e.desiredPolicy.Ready(); e.desiredPolicy.Detach()
	//   → removeUser → maybeDetachLocked → P DETACHED (the bug)
	epA.desiredPolicy.Ready()
	epA.desiredPolicy.Detach(logger)

	// --- Step 5: Endpoint A finishes leaving (leaveLocked line 1316) ---
	// identityManager.Remove → refCount 2→1, policyCache.delete does NOT fire
	idManager.Remove(podID)

	// --- Step 6: Endpoint B regenerates (real regeneratePolicy call) ---
	// This is the EXACT CI failure path: regeneratePolicy reads the detached P from
	// statedb via waitForPolicyComputationResult, then calls AddHold() which fails,
	// returning: "selector policy was detached, aborting regeneration"
	epB := Endpoint{
		policyRepo:       repo,
		policyFetcher:    polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: podID,
		identityManager:  idManager,
	}
	epB.UpdateLogger(nil)

	statsB := new(regenerationStatistics)
	regenCtxB := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epB.regeneratePolicy(statsB, regenCtxB)

	// WITHOUT FIX: err = "selector policy was detached, aborting regeneration"
	// WITH FIX: err = nil — P stayed idle, B's AddHold succeeded
	require.NoError(t, err,
		"endpoint B must not get 'selector policy was detached, aborting regeneration' (the CI failure)")
	require.NotNil(t, regenCtxB.policyResult.endpointPolicy,
		"endpoint B must get a valid EndpointPolicy")

	// --- Step 7: Cleanup — both endpoints gone ---
	regenCtxB.policyResult.endpointPolicy.Ready()
	regenCtxB.policyResult.endpointPolicy.Detach(logger)
	// refCount 1→0 → observer → policyCache.delete → detach(true, 0) → full cleanup
	idManager.Remove(podID)
}

// TestStaleStatedbEntryAfterIdentityDeleteReAdd reproduces the race condition
// from the "Cilium Cluster Mesh upgrade" CI failure (run 22842680257) where:
//
//  1. Endpoint A with identity X has policy computed (stored in statedb) and regenerates
//  2. Endpoint A leaves: desiredPolicy.Detach() then idManager.Remove() → refcount 1→0
//     → observer fires → policyCache.delete() → force detach + PolicyChangeDelete emitted
//     → handlePolicyCacheEvent: idmanager.Get() returns nil → SKIPS statedb deletion
//  3. Endpoint B arrives with same identity X: idManager.Add() → refcount 0→1
//     → policyCache.insert() → PolicyChangeInsert → handlePolicyCacheEvent
//     → RecomputeIdentityPolicy skips (stale entry still exists with sufficient revision)
//  4. Endpoint B regenerates: reads stale detached policy from statedb → AddHold() fails
//     → "selector policy was detached, aborting regeneration"
//
// Key difference from TestRemoveUserCausesRegenFailure: only ONE endpoint at a time
// (identity refcount drops to 0, triggering observer callbacks). The bug is in
// handlePolicyCacheEvent's DELETE handler not cleaning up statedb when the identity
// has already been removed from the identity manager.
//
// Without fix: test FAILS — stale statedb entry persists after identity removal,
// and endpoint B reads the detached policy from statedb.
// With fix: test PASSES — statedb entry properly deleted, fresh policy computed on re-add.
func TestStaleStatedbEntryAfterIdentityDeleteReAdd(t *testing.T) {
	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	logger := hivetest.Logger(t)
	idcache := make(identity.IdentityMap)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := compute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", "TestStaleStatedbEntryAfterIdentityDeleteReAdd", repo, idManager)

	// Create identity for our pod
	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

	// --- Step 1: Endpoint A arrives, compute policy ---
	idManager.Add(podID)

	epA := Endpoint{
		policyRepo:       repo,
		policyFetcher:    polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: podID,
		identityManager:  idManager,
	}
	epA.UpdateLogger(nil)

	// Add a policy rule so there's actual policy to compute
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
	_, rev := repo.MustAddList(api.Rules{rule})

	// Wait for the observer to be subscribed and process the INSERT event.
	// The observer subscribes asynchronously after h.Start(). Without this wait,
	// idManager.Remove() might fire before the observer subscribes, causing
	// the DELETE event to be lost (Multicast has no subscribers).
	require.Eventually(t, func() bool {
		_, _, _, found := polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
		return found
	}, 5*time.Second, 10*time.Millisecond,
		"observer must create statedb entry for identity")

	computePolicyForEPAndWait(t, &epA, polComputer, rev)

	// Verify: statedb entry exists with valid (non-detached) policy
	res, _, _, found := polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
	require.True(t, found, "statedb entry must exist after policy computation")
	require.NotNil(t, res.NewPolicy, "computed policy must not be nil")
	require.True(t, res.NewPolicy.AddHold(), "initial policy must not be detached")
	res.NewPolicy.MaybeDetach() // release the hold we just took

	// --- Step 2: Endpoint A regenerates successfully ---
	statsA := new(regenerationStatistics)
	regenCtxA := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epA.regeneratePolicy(statsA, regenCtxA)
	require.NoError(t, err, "endpoint A regeneration must succeed")
	require.NotNil(t, regenCtxA.policyResult.endpointPolicy)
	epA.desiredPolicy = regenCtxA.policyResult.endpointPolicy

	// --- Step 3: Endpoint A leaves completely (refcount drops to 0) ---
	// This triggers the full observer chain synchronously via Multicast emit:
	//   idManager.Remove() → policyCache.delete() → selPolicy.detach(true, 0)
	//   → emitChange(DELETE) → handlePolicyCacheEvent(DELETE) runs inline
	//   With fix: statedb entry is deleted.
	//   Without fix: idmanager.Get() returns nil → early return → stale entry remains.
	epA.desiredPolicy.Ready()
	epA.desiredPolicy.Detach(logger)
	idManager.Remove(podID) // refcount 1→0, observer fires synchronously

	// Verify: statedb entry must be GONE after identity removal.
	// This is the core assertion — without the fix, the DELETE handler in
	// handlePolicyCacheEvent skips cleanup because idmanager.Get() returns nil
	// (identity already removed from the manager), leaving a stale entry.
	_, _, _, found = polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
	require.False(t, found, "statedb entry must be deleted after identity removal (refcount→0)")

	// --- Step 4: Endpoint B arrives with same identity ---
	// idManager.Add → refcount 0→1 → policyCache.insert() → emitChange(INSERT)
	// → handlePolicyCacheEvent(INSERT) calls RecomputeIdentityPolicy(identity, 0)
	//   which launches an async goroutine to compute fresh policy.
	idManager.Add(podID)

	epB := Endpoint{
		policyRepo:       repo,
		policyFetcher:    polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: podID,
		identityManager:  idManager,
	}
	epB.UpdateLogger(nil)

	// Wait for the INSERT handler's recomputation goroutine to complete.
	computePolicyForEPAndWait(t, &epB, polComputer, rev)

	// Verify: statedb entry must exist with a fresh, non-detached policy.
	res, _, _, found = polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
	require.True(t, found, "statedb entry must exist after identity re-add")
	require.NotNil(t, res.NewPolicy, "recomputed policy must not be nil")
	require.True(t, res.NewPolicy.AddHold(), "recomputed policy must not be detached")
	res.NewPolicy.MaybeDetach() // release the hold we just took

	// --- Step 5: Endpoint B regenerates ---
	statsB := new(regenerationStatistics)
	regenCtxB := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epB.regeneratePolicy(statsB, regenCtxB)
	require.NoError(t, err,
		"endpoint B must not get 'selector policy was detached' error after identity delete/re-add")
	require.NotNil(t, regenCtxB.policyResult.endpointPolicy,
		"endpoint B must get a valid EndpointPolicy")

	// --- Cleanup ---
	regenCtxB.policyResult.endpointPolicy.Ready()
	regenCtxB.policyResult.endpointPolicy.Detach(logger)
	idManager.Remove(podID)
}

// TestSkippedPolicyRevisionPropagatedThroughDuplicateRegen reproduces the race seen in
// Conformance Delegated IPAM CI failure (run 22909093096): endpoint 1477 got stuck at
// datapathPolicyRevision=198 while the current policy revision was 199, because:
//
//  1. PeriodicRegeneration fires, endpoint enters StateWaitingToRegenerate (queued at rev=198)
//  2. New policy arrives → PolicyUpdate fires with rev=199
//  3. PolicyUpdate is SKIPPED (endpoint already waiting-to-regenerate) — rev=199 dropped
//  4. The queued regen runs with policyRevisionToWaitFor=198; statedb returns 198 → done
//  5. Endpoint finishes at datapathPolicyRevision=198; no regen triggered for rev=199 → stuck
//
// The fix mirrors the existing skippedRegenerationLevel mechanism: store the highest
// skipped PolicyRevisionToWaitFor in ep.skippedPolicyRevision, then apply it to the
// datapathRegenerationContext just before regeneratePolicy is called in regenerate().
func TestSkippedPolicyRevisionPropagatedThroughDuplicateRegen(t *testing.T) {
	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	logger := hivetest.Logger(t)
	idcache := make(identity.IdentityMap)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := compute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", "TestSkippedPolicyRevisionPropagatedThroughDuplicateRegen", repo, idManager)

	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

	// IMPORTANT: Add podID to idManager BEFORE adding any policy rules.
	// This ensures the observer fires with an empty repo (rev=0), so statedb starts at rev0
	// and doesn't jump to the latest repo revision. Per-subtest explicit
	// computePolicyForEPAndWait calls then control exactly what revision is in statedb.
	idManager.Add(podID)
	// Wait for the observer to complete its initial computation (at rev=0, no rules).
	require.Eventually(t, func() bool {
		_, _, _, found := polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
		return found
	}, 5*time.Second, 1*time.Millisecond, "observer must compute initial statedb entry")

	podSelectLabel := labels.ParseSelectLabel("pod")
	egressSelectLabel := labels.ParseSelectLabel("peer")

	makeRule := func(name string) *api.Rule {
		return &api.Rule{
			EndpointSelector: api.NewESFromLabels(podSelectLabel),
			EgressDeny: []api.EgressDenyRule{{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(egressSelectLabel)},
				},
				ToPorts: []api.PortDenyRule{{Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}}}},
			}},
			Labels: labels.LabelArray{
				labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceAny),
			},
		}
	}

	// Add rules AFTER idManager.Add so the observer does NOT auto-recompute statedb at these revisions.
	// Each subtest controls statedb explicitly via computePolicyForEPAndWait.
	_, rev198 := repo.MustAddList(api.Rules{makeRule("rule-198")})
	_, rev199 := repo.MustAddList(api.Rules{makeRule("rule-199")})
	_, rev200 := repo.MustAddList(api.Rules{makeRule("rule-200")})

	newEP := func() *Endpoint {
		ep := &Endpoint{
			policyRepo:       repo,
			policyFetcher:    polComputer,
			desiredPolicy:    policy.NewEndpointPolicy(logger, repo),
			labels:           labels.NewOpLabels(),
			SecurityIdentity: podID,
			identityManager:  idManager,
			status:           NewEndpointStatus(),
		}
		ep.UpdateLogger(nil)
		return ep
	}

	// triggerDuplicateSkip calls setRegenerateStateLocked under ep.mutex and returns
	// whether the trigger was skipped (i.e., setRegenerateStateLocked returned false).
	triggerDuplicateSkip := func(ep *Endpoint, rev uint64) (skipped bool) {
		meta := &regeneration.ExternalRegenerationMetadata{
			Reason:                  regeneration.ReasonPolicyUpdate,
			RegenerationLevel:       regeneration.RegenerateWithoutDatapath,
			PolicyRevisionToWaitFor: rev,
		}
		ep.unconditionalLock()
		regen := ep.setRegenerateStateLocked(meta)
		ep.unlock()
		return !regen // skipped = regen was NOT triggered
	}

	// consumeSkipped calls the real production method (consumeSkippedPolicyRevision)
	// under the endpoint mutex, exactly as regenerate() does.
	consumeSkipped := func(ep *Endpoint, ctx *datapathRegenerationContext) {
		ep.unconditionalLock()
		ep.consumeSkippedPolicyRevision(ctx)
		ep.unlock()
	}

	t.Run("BasicCaptureAndPropagate", func(t *testing.T) {
		// Reproduces the exact CI failure: PolicyUpdate for rev199 is skipped while
		// the endpoint is in StateWaitingToRegenerate. Statedb is at rev198 only (simulating
		// the race window where the identity-policy-computer hasn't yet written rev199).
		//
		// WITHOUT fix: regen uses policyRevisionToWaitFor=rev198; statedb returns rev198 →
		//              completes at rev198; rev199 policy is never applied → endpoint stuck.
		// WITH fix:    skippedPolicyRevision=rev199 bumps policyRevisionToWaitFor to rev199;
		//              regen blocks until statedb has rev199 → completes at rev199 ✓
		ep := newEP()

		// Compute statedb at rev198 ONLY (statedb was at rev0; now it's rev198).
		computePolicyForEPAndWait(t, ep, polComputer, rev198)

		// Endpoint enters StateWaitingToRegenerate (e.g., from PeriodicRegeneration at rev198).
		ep.state = StateWaitingToRegenerate

		// PolicyUpdate for rev199 fires — SKIPPED (duplicate).
		require.True(t, triggerDuplicateSkip(ep, rev199))

		// Fix: skippedPolicyRevision must capture the dropped revision.
		require.Equal(t, rev199, ep.skippedPolicyRevision,
			"skippedPolicyRevision must be set on duplicate PolicyUpdate skip [BUG: field never set without fix]")

		// The queued regen event carries the OLD policyRevisionToWaitFor (rev198).
		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev198}
		consumeSkipped(ep, ctx)

		require.Equal(t, rev199, ctx.policyRevisionToWaitFor,
			"policyRevisionToWaitFor must be bumped to rev199 [BUG: stays at rev198 without fix]")

		// Compute statedb at rev199 so waitForPolicyComputationResult can satisfy the wait.
		// Note: ComputeSelectorPolicy returns the current repo revision (rev200=4 since all
		// three rules are already added to the repo), so statedb will have rev200 here.
		// The important behavioral guarantees are already tested above via the
		// skippedPolicyRevision and ctx.policyRevisionToWaitFor assertions.
		computePolicyForEPAndWait(t, ep, polComputer, rev199)

		// Smoke-test: run regeneratePolicy to confirm the bumped context works end-to-end.
		// Note: ComputeSelectorPolicy always returns the current repo revision (rev200),
		// so policyResult.policyRevision will be rev200 regardless of the fix. The real
		// bug-vs-fix distinction is tested by the assertions above on skippedPolicyRevision
		// and ctx.policyRevisionToWaitFor.
		ep.state = StateRegenerating
		require.NoError(t, ep.regeneratePolicy(new(regenerationStatistics), ctx))
	})

	t.Run("LowerRevisionNotDecremented", func(t *testing.T) {
		// A skipped PolicyUpdate with a LOWER revision must NOT decrease skippedPolicyRevision.
		ep := newEP()
		ep.state = StateWaitingToRegenerate
		ep.skippedPolicyRevision = rev199 // pre-set from a prior higher-rev skip

		require.True(t, triggerDuplicateSkip(ep, rev198)) // lower revision
		require.Equal(t, rev199, ep.skippedPolicyRevision,
			"skippedPolicyRevision must not decrease when a lower revision is skipped")
	})

	t.Run("MultipleSkipsTracksMax", func(t *testing.T) {
		// Multiple duplicate skips accumulate to the highest seen revision.
		ep := newEP()
		ep.state = StateWaitingToRegenerate

		triggerDuplicateSkip(ep, rev199)
		require.Equal(t, rev199, ep.skippedPolicyRevision)

		triggerDuplicateSkip(ep, rev200)
		require.Equal(t, rev200, ep.skippedPolicyRevision, "must track the higher revision")

		triggerDuplicateSkip(ep, rev199)
		require.Equal(t, rev200, ep.skippedPolicyRevision, "must not decrease from rev200")

		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev198}
		consumeSkipped(ep, ctx)
		require.Equal(t, rev200, ctx.policyRevisionToWaitFor)

		// Smoke-test: confirm regeneratePolicy completes without error.
		// policyResult.policyRevision == rev200 here because ComputeSelectorPolicy
		// returns the current repo revision; the real assertion is the
		// policyRevisionToWaitFor == rev200 check above.
		computePolicyForEPAndWait(t, ep, polComputer, rev200)
		ep.state = StateRegenerating
		require.NoError(t, ep.regeneratePolicy(new(regenerationStatistics), ctx))
	})

	t.Run("ResetAfterConsume", func(t *testing.T) {
		// skippedPolicyRevision must be cleared to 0 after regenerate() consumes it,
		// so the next regen cycle starts fresh.
		ep := newEP()
		ep.state = StateWaitingToRegenerate
		triggerDuplicateSkip(ep, rev199)
		require.Equal(t, rev199, ep.skippedPolicyRevision)

		// Simulate consume (what regenerate() does with the fix):
		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev198}
		consumeSkipped(ep, ctx)
		require.Equal(t, uint64(0), ep.skippedPolicyRevision, "must be cleared after consume")

		// After reset, a subsequent skip at rev198 is tracked from zero.
		ep.state = StateWaitingToRegenerate
		triggerDuplicateSkip(ep, rev198)
		require.Equal(t, rev198, ep.skippedPolicyRevision,
			"after reset, new skips are tracked from zero")
	})

	t.Run("ContextAlreadyHigher", func(t *testing.T) {
		// If the context's policyRevisionToWaitFor is already HIGHER than
		// skippedPolicyRevision, consumeSkippedPolicyRevision must be a no-op.
		ep := newEP()
		ep.state = StateWaitingToRegenerate
		triggerDuplicateSkip(ep, rev199) // skippedPolicyRevision = rev199

		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev200} // higher
		consumeSkipped(ep, ctx)
		require.Equal(t, rev200, ctx.policyRevisionToWaitFor,
			"context revision must not be lowered when skippedPolicyRevision < ctx revision")
	})

	t.Run("FreshRegenDoesNotSetSkippedRevision", func(t *testing.T) {
		// When setRegenerateStateLocked transitions an endpoint to
		// StateWaitingToRegenerate for the FIRST TIME (not a duplicate),
		// skippedPolicyRevision must NOT be updated.
		ep := newEP()
		// ep.state is the zero value (not StateWaitingToRegenerate), so this
		// is a fresh trigger, not a duplicate.
		meta := &regeneration.ExternalRegenerationMetadata{
			Reason:                  regeneration.ReasonPolicyUpdate,
			RegenerationLevel:       regeneration.RegenerateWithoutDatapath,
			PolicyRevisionToWaitFor: rev199,
		}
		ep.unconditionalLock()
		ep.setRegenerateStateLocked(meta) // ignore return; only testing side-effect on skippedPolicyRevision
		ep.unlock()

		require.Equal(t, uint64(0), ep.skippedPolicyRevision,
			"fresh regen trigger must not set skippedPolicyRevision")
	})
}
