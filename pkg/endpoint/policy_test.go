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
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/compute"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
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
	repo := policy.NewPolicyRepository(logger, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := testcompute.InstantiateCellForTesting(t, logger, "endpoint-policy_test", t.Name(), repo, idManager)

	podLbls := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID, _, err := fakeAllocator.AllocateIdentity(context.Background(), podLbls, false, 0)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{podID.ID: podID.LabelArray}, nil, wg)
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

// fakePolicyMap is a minimal in-memory implementation of policymap.PolicyMap
// sufficient to exercise Endpoint.syncPolicyMapWith without any real BPF
// interaction. It round-trips through the same PolicyKey/PolicyEntry
// conversion helpers production code uses.
type fakePolicyMap struct {
	entries map[policymap.PolicyKey]policymap.PolicyEntry
}

func newFakePolicyMap() *fakePolicyMap {
	return &fakePolicyMap{entries: make(map[policymap.PolicyKey]policymap.PolicyEntry)}
}

func (f *fakePolicyMap) Update(key *policymap.PolicyKey, entry *policymap.PolicyEntry) error {
	f.entries[*key] = *entry
	return nil
}

func (f *fakePolicyMap) DeleteKey(key policymap.PolicyKey) error {
	delete(f.entries, key)
	return nil
}

func (f *fakePolicyMap) DeleteEntry(entry *policymap.PolicyEntryDump) error {
	delete(f.entries, entry.Key)
	return nil
}

func (f *fakePolicyMap) String() string { return "fakePolicyMap" }

func (f *fakePolicyMap) Dump() (string, error) { return "", nil }

func (f *fakePolicyMap) DumpToSlice() (policymap.PolicyEntriesDump, error) {
	out := make(policymap.PolicyEntriesDump, 0, len(f.entries))
	for k, v := range f.entries {
		out = append(out, policymap.PolicyEntryDump{Key: k, PolicyEntry: v})
	}
	return out, nil
}

func (f *fakePolicyMap) DumpToMapStateMap() (policy.MapStateMap, error) {
	out := make(policy.MapStateMap, len(f.entries))
	for k, v := range f.entries {
		policyKey := policy.KeyForDirection(trafficdirection.TrafficDirection(k.TrafficDirection)).
			WithIdentity(identity.NumericIdentity(k.Identity)).
			WithPortProtoPrefix(u8proto.U8proto(k.Nexthdr), k.GetDestPort(), k.GetPortPrefixLen())
		out[policyKey] = policy.MapStateEntry{
			Precedence:      v.Precedence,
			ProxyPort:       v.GetProxyPort(),
			AuthRequirement: v.AuthRequirement,
			Cookie:          v.Cookie,
		}.WithDeny(v.IsDeny())
	}
	return out, nil
}

func (f *fakePolicyMap) MaxEntries() uint32 { return 16384 }

func (f *fakePolicyMap) Close() error { return nil }

// noopPolicyMapPressureUpdater satisfies policyMapPressureUpdater without
// wiring up real metrics.
type noopPolicyMapPressureUpdater struct{}

func (noopPolicyMapPressureUpdater) Update(PolicyMapPressureEvent) {}
func (noopPolicyMapPressureUpdater) Remove(uint16)                 {}

// TestRevertFirstRegenFailurePreservesWildcardEntries is a regression test for
// GH-44855: policy-enabled=none, first-ever BPF regeneration fails after the
// policyMap has been opened and the pre-compile sync has written wildcard
// allow entries, but before the BPF program is compiled/loaded.
//
// The revert logic introduced by GH-38998 rolls e.desiredPolicy back to
// e.realizedPolicy and syncs the BPF map to match it. For a brand-new
// endpoint, e.realizedPolicy is still the empty stub from NewEndpointPolicy.
// Without the fix, syncing against that empty stub deletes the wildcard
// entries that were just written, permanently blackholing traffic even
// though policy enforcement is disabled (subsequent successful regenerations
// never change anything because desiredPolicy == realizedPolicy, the same
// empty object). With the fix, the stub is repaired with wildcard entries
// before the sync, so the entries survive the revert.
func TestRevertFirstRegenFailurePreservesWildcardEntries(t *testing.T) {
	f := newPolicyTestFixture(t)
	logger := hivetest.Logger(t)

	// A brand-new endpoint: desiredPolicy and realizedPolicy both point at
	// the same empty stub, exactly as NewEndpoint sets them up.
	stub := policy.NewEndpointPolicy(logger, f.repo)
	ep := &Endpoint{
		policyRepo:               f.repo,
		desiredPolicy:            stub,
		realizedPolicy:           stub,
		SecurityIdentity:         f.podID,
		PolicyMapPressureUpdater: noopPolicyMapPressureUpdater{},
	}
	ep.UpdateLogger(nil)

	fakeMap := newFakePolicyMap()
	ep.policyMap = fakeMap

	// Policy enforcement is disabled on both directions (the zero value for a
	// fresh selectorPolicy already reflects this).
	require.False(t, stub.SelectorPolicy.IngressPolicyEnabled)
	require.False(t, stub.SelectorPolicy.EgressPolicyEnabled)

	// Simulate the policy computed for the endpoint's first-ever regeneration:
	// enforcement still disabled, so DistillPolicy would have populated
	// wildcard allow entries in both directions.
	newDesired := policy.NewEndpointPolicy(logger, f.repo)
	newDesired.AllowAllIdentities(true, true)
	require.False(t, newDesired.Empty())

	datapathRegenCtxt := &datapathRegenerationContext{
		policyResult: &policyGenerateResult{
			endpointPolicy:   newDesired,
			identity:         f.podID.ID,
			identityRevision: ep.identityRevision,
		},
	}

	require.NoError(t, ep.setDesiredPolicy(datapathRegenCtxt))
	require.Same(t, newDesired, ep.desiredPolicy)
	require.False(t, datapathRegenCtxt.revertStack.Empty())

	// Simulate runPreCompilationSteps' pre-compile sync: the (still empty)
	// BPF map gets synced up to the new desired policy, writing the
	// wildcard allow entries into the map.
	_, _, err := ep.syncPolicyMapWith(policy.MapStateMap{}, false, false)
	require.NoError(t, err)
	preRevertDump, err := fakeMap.DumpToMapStateMap()
	require.NoError(t, err)
	require.NotEmpty(t, preRevertDump, "pre-compile sync should have written wildcard entries")

	// Now simulate the BPF compile/load step failing: finalizeEndpointRegeneration
	// runs the revert stack.
	require.NoError(t, datapathRegenCtxt.revertStack.Revert())

	// The endpoint must have reverted back to (a repaired) realizedPolicy...
	require.Same(t, ep.realizedPolicy, ep.desiredPolicy)

	// ...and, critically, the BPF map must still contain the wildcard allow
	// entries: policy enforcement is disabled, so the datapath must keep
	// allowing all traffic, not drop everything.
	postRevertDump, err := fakeMap.DumpToMapStateMap()
	require.NoError(t, err)
	require.NotEmpty(t, postRevertDump, "revert must not delete wildcard allow entries when policy enforcement is disabled")
	require.Equal(t, len(preRevertDump), len(postRevertDump))
}

// TestRevertOntoRealizedDenyAllDoesNotOpenTraffic guards the wildcard-repair
// added for GH-44855 against over-firing. The repair is only correct for the
// pristine NewEndpointPolicy stub (PolicyOwner == nil). A real, previously
// realized policy can legitimately be Empty() too: enforcement enabled on a
// direction with a default-deny outcome and no selecting rules produces an
// empty map state. Such a policy has PolicyOwner set, so IsValid() is true.
//
// If a later regeneration flips enforcement off on one direction and then fails,
// the revert path must NOT inject wildcard allow entries onto that real
// deny-all policy. Doing so would silently open traffic that must stay denied.
// The guard must therefore key on !IsValid(), not on Empty() alone.
func TestRevertOntoRealizedDenyAllDoesNotOpenTraffic(t *testing.T) {
	f := newPolicyTestFixture(t)
	logger := hivetest.Logger(t)

	ep := &Endpoint{
		policyRepo:               f.repo,
		SecurityIdentity:         f.podID,
		PolicyMapPressureUpdater: noopPolicyMapPressureUpdater{},
	}
	ep.UpdateLogger(nil)

	// realizedPolicy is a *real* policy that was already realized successfully:
	// PolicyOwner is set (IsValid() == true), enforcement is on for both
	// directions, and it is a default-deny with no selecting rules, so its map
	// state is empty (Empty() == true). This is the exact shape the Empty()-only
	// guard fails to distinguish from the pristine first-regen stub.
	realized := policy.NewEndpointPolicy(logger, f.repo)
	realized.PolicyOwner = ep
	realized.SelectorPolicy.IngressPolicyEnabled = true
	realized.SelectorPolicy.EgressPolicyEnabled = true
	require.True(t, realized.IsValid(), "realized policy must look like a real, computed policy")
	require.True(t, realized.Empty(), "a default-deny policy with no selecting rules is legitimately empty")

	ep.desiredPolicy = realized
	ep.realizedPolicy = realized

	fakeMap := newFakePolicyMap()
	ep.policyMap = fakeMap

	// The BPF map reflects the realized deny-all policy: no allow entries.
	// This is the state the datapath must be kept in on a failed revert.
	preRevertDump, err := fakeMap.DumpToMapStateMap()
	require.NoError(t, err)
	require.Empty(t, preRevertDump, "deny-all realized policy has no allow entries in the map")

	// A new regeneration flips egress enforcement OFF (ingress stays on) and
	// computes a new desired policy that allows all egress. Enforcement being
	// disabled on egress is what arms the repair branch in the revert closure.
	newDesired := policy.NewEndpointPolicy(logger, f.repo)
	newDesired.PolicyOwner = ep
	newDesired.SelectorPolicy.IngressPolicyEnabled = true
	newDesired.SelectorPolicy.EgressPolicyEnabled = false
	newDesired.AllowAllIdentities(false, true)

	datapathRegenCtxt := &datapathRegenerationContext{
		policyResult: &policyGenerateResult{
			endpointPolicy:   newDesired,
			identity:         f.podID.ID,
			identityRevision: ep.identityRevision,
		},
	}

	require.NoError(t, ep.setDesiredPolicy(datapathRegenCtxt))
	require.Same(t, newDesired, ep.desiredPolicy)
	require.False(t, datapathRegenCtxt.revertStack.Empty())

	// The BPF compile/load step fails and the revert stack runs, rolling back
	// onto the realized deny-all policy.
	require.NoError(t, datapathRegenCtxt.revertStack.Revert())
	require.Same(t, ep.realizedPolicy, ep.desiredPolicy)

	// The realized policy is a real deny-all, so the revert must leave the map
	// exactly as it was: no wildcard allow entries injected. If the guard keyed
	// on Empty() alone it would call AllowAllIdentities(false, true) here and
	// open egress that the policy requires to stay denied.
	postRevertDump, err := fakeMap.DumpToMapStateMap()
	require.NoError(t, err)
	require.Empty(t, postRevertDump, "revert onto a real deny-all policy must not inject wildcard allow entries")
	require.True(t, ep.realizedPolicy.Empty(), "realized deny-all policy must not have been mutated into allow-all")
}
