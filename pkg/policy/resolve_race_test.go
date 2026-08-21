// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// racingPolicyOwner mimics the endpoint's locking: the current EndpointPolicy is mutated by
// incremental map changes while holding 'mutex', which is the only lock a policy recomputation
// can use to synchronize with it. The selector cache read lock held by DistillPolicy provides no
// mutual exclusion here, as incremental changes are applied without it.
type racingPolicyOwner struct {
	DummyOwner

	mutex   lock.RWMutex
	current *EndpointPolicy
}

func (o *racingPolicyOwner) PreviousMapStateSizes() MapStateSizes {
	o.mutex.RLock()
	defer o.mutex.RUnlock()
	return o.current.GetMapState().Sizes()
}

// TestDistillPolicyMapStateRace checks that deriving the map state of a new EndpointPolicy from
// the owner's current one does not race with incremental map changes applied to that current
// policy. Run with -race.
func TestDistillPolicyMapStateRace(t *testing.T) {
	logger := hivetest.Logger(t)

	sp := &selectorPolicy{
		Revision:      1,
		SelectorCache: testNewSelectorCache(t, logger, nil),
		L4Policy:      NewL4Policy(1),
	}
	// named port rules make the map state maintain the identity index ('byId') that both the
	// reader and the writer touch.
	sp.L4Policy.Ingress.features.setFeature(namedPortRules)
	features := sp.L4Policy.Ingress.features | sp.L4Policy.Egress.features

	current := &EndpointPolicy{
		SelectorPolicy:   sp,
		policyMapState:   newMapState(logger, MapStateSizes{}, features),
		policyMapChanges: MapChanges{logger: logger},
	}
	// the id index must be in use for the race on it to be covered
	require.NotNil(t, current.policyMapState.byId)
	owner := &racingPolicyOwner{
		DummyOwner: DummyOwner{logger: logger},
		current:    current,
	}
	current.PolicyOwner = owner

	const numIdentities = 128
	key := egressKey(0, u8proto.TCP, 80, 0)
	entry := newMapStateEntry(0, types.HighestPriority, types.LowestPriority, NilRuleOrigin, 0, 0, types.Allow, NoAuthRequirement)
	for i := range numIdentities {
		current.policyMapState.upsert(key.WithIdentity(identity.NumericIdentity(i+1000)), entry)
	}

	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: incremental map changes, as applied by Endpoint.ApplyPolicyMapChanges while
	// holding the endpoint lock.
	go func() {
		defer wg.Done()
		for i := range iterations {
			id := identity.NumericIdentity(i%numIdentities + 1000)
			owner.mutex.Lock()
			current.policyMapChanges.AccumulateMapChanges(0, 0,
				identity.NumericIdentitySlice{id}, nil, key, entry)
			current.policyMapChanges.SyncMapChanges(types.MockSelectorSnapshot())
			current.policyMapChanges.consumeMapChanges(current, features)

			current.policyMapChanges.AccumulateMapChanges(0, 0,
				nil, identity.NumericIdentitySlice{id}, key, entry)
			current.policyMapChanges.SyncMapChanges(types.MockSelectorSnapshot())
			current.policyMapChanges.consumeMapChanges(current, features)
			owner.mutex.Unlock()
		}
	}()

	// Reader: policy recomputation, which runs with the endpoint unlocked.
	go func() {
		defer wg.Done()
		for range iterations {
			ep := sp.DistillPolicy(logger, owner, nil)
			ep.Ready()
			ep.Detach(logger)
		}
	}()

	wg.Wait()
}

// TestDistillPolicyLockOrder guards the lock order documented in DistillPolicy: the map state
// sizes accessor takes the PolicyOwner's lock, and the owner takes the selector cache write
// lock while holding its own lock (as the endpoint's setDesiredPolicy does via Detach), so the
// accessor must be called before the selector cache read lock is taken. Calling it inside
// 'WithRLock' inverts the order and deadlocks this test.
func TestDistillPolicyLockOrder(t *testing.T) {
	logger := hivetest.Logger(t)

	sp := &selectorPolicy{
		Revision:      1,
		SelectorCache: testNewSelectorCache(t, logger, nil),
		L4Policy:      NewL4Policy(1),
	}
	sp.L4Policy.Ingress.features.setFeature(namedPortRules)

	current := &EndpointPolicy{
		SelectorPolicy:   sp,
		policyMapState:   emptyMapState(logger),
		policyMapChanges: MapChanges{logger: logger},
	}
	owner := &racingPolicyOwner{
		DummyOwner: DummyOwner{logger: logger},
		current:    current,
	}
	current.PolicyOwner = owner

	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(2)

	// Owner: takes the selector cache write lock while holding its own lock, as the endpoint
	// does when setDesiredPolicy detaches a superseded policy (Detach -> removeUser ->
	// finishDetach -> RemoveSelectors).
	go func() {
		defer wg.Done()
		sc := sp.SelectorCache
		for range iterations {
			owner.mutex.Lock()
			sc.mutex.Lock()
			sc.mutex.Unlock()
			owner.mutex.Unlock()
		}
	}()

	// Recomputation: DistillPolicy takes the owner's lock for the sizes snapshot before the
	// selector cache read lock.
	go func() {
		defer wg.Done()
		for range iterations {
			ep := sp.DistillPolicy(logger, owner, nil)
			ep.Ready()
			ep.Detach(logger)
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("deadlock: DistillPolicy did not complete against the selector cache write lock taken under the owner lock")
	}
}
