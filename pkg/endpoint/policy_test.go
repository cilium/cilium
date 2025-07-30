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

// TestRemoveUserCausesRegenFailure reproduces a race where two endpoints share
// an identity, endpoint A leaves (refcount stays >0 so no observer fires), and
// removeUser detaches the selectorPolicy that endpoint B is about to use.
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

	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

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

	statsA := new(regenerationStatistics)
	regenCtxA := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epA.regeneratePolicy(statsA, regenCtxA)
	require.NoError(t, err)
	require.NotNil(t, regenCtxA.policyResult.endpointPolicy)

	// Reassign so Detach() calls removeUser on the correct selectorPolicy.
	epA.desiredPolicy = regenCtxA.policyResult.endpointPolicy

	// refCount 1\u21922; no observer fires since identity is already tracked.
	idManager.Add(podID)

	epA.desiredPolicy.Ready()
	epA.desiredPolicy.Detach(logger)

	// refCount 2\u21921; policyCache.delete does NOT fire (still >0).
	idManager.Remove(podID)

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
	require.NoError(t, err)
	require.NotNil(t, regenCtxB.policyResult.endpointPolicy)

	regenCtxB.policyResult.endpointPolicy.Ready()
	regenCtxB.policyResult.endpointPolicy.Detach(logger)
	idManager.Remove(podID)
}

// TestStaleStatedbEntryAfterIdentityDeleteReAdd covers the single-endpoint case
// where identity refcount drops to 0. The DELETE handler in handlePolicyCacheEvent
// must clean up the statedb entry even though the identity is already gone from
// idmanager — otherwise the next endpoint for this identity reads stale detached
// policy.
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

	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

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

	// Observer subscribes async; wait so the DELETE event isn't lost.
	require.Eventually(t, func() bool {
		_, _, _, found := polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
		return found
	}, 5*time.Second, 10*time.Millisecond,
		"observer must create statedb entry for identity")

	computePolicyForEPAndWait(t, &epA, polComputer, rev)

	res, _, _, found := polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
	require.True(t, found)
	require.NotNil(t, res.NewPolicy)
	require.True(t, res.NewPolicy.AddHold())
	res.NewPolicy.MaybeDetach()

	statsA := new(regenerationStatistics)
	regenCtxA := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epA.regeneratePolicy(statsA, regenCtxA)
	require.NoError(t, err)
	require.NotNil(t, regenCtxA.policyResult.endpointPolicy)
	epA.desiredPolicy = regenCtxA.policyResult.endpointPolicy

	epA.desiredPolicy.Ready()
	epA.desiredPolicy.Detach(logger)
	idManager.Remove(podID)

	// DELETE handler must clean up statedb even when the identity is already
	// gone from idmanager.
	_, _, _, found = polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
	require.False(t, found, "statedb entry must be deleted after identity removal")

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

	computePolicyForEPAndWait(t, &epB, polComputer, rev)

	res, _, _, found = polComputer.GetIdentityPolicyByNumericIdentity(podID.ID)
	require.True(t, found)
	require.NotNil(t, res.NewPolicy)
	require.True(t, res.NewPolicy.AddHold())
	res.NewPolicy.MaybeDetach()

	statsB := new(regenerationStatistics)
	regenCtxB := &datapathRegenerationContext{policyRevisionToWaitFor: rev}
	err = epB.regeneratePolicy(statsB, regenCtxB)
	require.NoError(t, err)
	require.NotNil(t, regenCtxB.policyResult.endpointPolicy)

	regenCtxB.policyResult.endpointPolicy.Ready()
	regenCtxB.policyResult.endpointPolicy.Detach(logger)
	idManager.Remove(podID)
}

// TestMaybeDetachRaceDuringRegeneration reproduces the TOCTOU between reading
// a selectorPolicy from statedb and calling AddHold on it. A concurrent
// recomputation can MaybeDetach the policy in that window, causing
// "selector policy was detached, aborting regeneration". The fix moves
// AddHold into the waitForPolicyComputationResult loop so that on failure
// the loop waits on the watch channel for the replacement entry.
func TestMaybeDetachRaceDuringRegeneration(t *testing.T) {
	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	logger := hivetest.Logger(t)
	idcache := make(identity.IdentityMap)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := compute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", "TestMaybeDetachRaceDuringRegeneration", repo, idManager)

	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
	wg.Wait()

	idManager.Add(podID)

	podSelectLabel := labels.ParseSelectLabel("pod")
	makeRule := func(name, peer, port string) *api.Rule {
		return &api.Rule{
			EndpointSelector: api.NewESFromLabels(podSelectLabel),
			EgressDeny: []api.EgressDenyRule{{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel(peer)),
					},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{{Port: port, Protocol: "TCP"}},
				}},
			}},
			Labels: labels.LabelArray{
				labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceAny),
			},
		}
	}

	_, rev1 := repo.MustAddList(api.Rules{makeRule("r1", "peer", "80")})
	done, err := polComputer.RecomputeIdentityPolicy(podID, rev1)
	require.NoError(t, err)
	<-done

	// Verify initial policy is live, then detach it (MaybeDetach sets
	// superseded and detaches since there are no users or holds).
	res, _, _, found := polComputer.GetIdentityPolicyByIdentity(podID)
	require.True(t, found)
	require.True(t, res.NewPolicy.AddHold())
	res.NewPolicy.MaybeDetach()

	// Recompute to get a fresh, live policy in statedb.
	_, rev2 := repo.MustAddList(api.Rules{makeRule("r2", "peer2", "443")})
	done, err = polComputer.RecomputeIdentityPolicy(podID, rev2)
	require.NoError(t, err)
	<-done

	res, _, _, found = polComputer.GetIdentityPolicyByIdentity(podID)
	require.True(t, found)

	// Simulate compute.go superseding this policy before any endpoint holds it.
	res.NewPolicy.MaybeDetach()
	require.False(t, res.NewPolicy.AddHold(), "policy must be detached")

	// After a delay, write a replacement entry so the watch loop can succeed.
	_, rev3 := repo.MustAddList(api.Rules{makeRule("r3", "peer3", "8080")})
	go func() {
		time.Sleep(100 * time.Millisecond)
		done, err := polComputer.RecomputeIdentityPolicy(podID, rev3)
		if err == nil {
			<-done
		}
	}()

	// Endpoint reads the detached policy from statedb. Without the fix,
	// AddHold fails and regeneratePolicy returns an error. With the fix,
	// the loop waits for the replacement written by the goroutine above.
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
	regenCtxB := &datapathRegenerationContext{policyRevisionToWaitFor: rev2}
	err = epB.regeneratePolicy(statsB, regenCtxB)
	require.NoError(t, err)
	require.NotNil(t, regenCtxB.policyResult.endpointPolicy)

	regenCtxB.policyResult.endpointPolicy.Ready()
	regenCtxB.policyResult.endpointPolicy.Detach(logger)
	idManager.Remove(podID)
}

// TestSkippedPolicyRevisionPropagatedThroughDuplicateRegen reproduces a race where
// a duplicate regen trigger drops a higher PolicyRevisionToWaitFor:
//
//  1. PeriodicRegeneration fires, endpoint enters StateWaitingToRegenerate (queued at rev=198)
//  2. New policy arrives \u2192 PolicyUpdate fires with rev=199
//  3. PolicyUpdate is SKIPPED (endpoint already waiting-to-regenerate) \u2014 rev=199 dropped
//  4. The queued regen runs with policyRevisionToWaitFor=198; statedb returns 198 \u2192 done
//  5. Endpoint finishes at datapathPolicyRevision=198; no regen triggered for rev=199 \u2192 stuck
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

	// Must precede rule additions so observer starts at rev=0 and subtests
	// control statedb revision explicitly.
	idManager.Add(podID)
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
		// PolicyUpdate for rev199 is skipped while the endpoint is queued at rev198.
		ep := newEP()

		computePolicyForEPAndWait(t, ep, polComputer, rev198)

		ep.state = StateWaitingToRegenerate

		require.True(t, triggerDuplicateSkip(ep, rev199))

		require.Equal(t, rev199, ep.skippedPolicyRevision)

		// The queued regen carries the old policyRevisionToWaitFor (rev198).
		ctx := &datapathRegenerationContext{policyRevisionToWaitFor: rev198}
		consumeSkipped(ep, ctx)

		require.Equal(t, rev199, ctx.policyRevisionToWaitFor)

		computePolicyForEPAndWait(t, ep, polComputer, rev199)

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
