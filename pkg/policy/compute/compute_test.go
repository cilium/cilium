// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

// TestWatchChannelFiresOnUpdate verifies that a statedb watch channel obtained
// via the production GetIdentityPolicyByIdentity / GetIdentityPolicyByNumericIdentity
// code path is closed when a subsequent WriteTxn modifies the same key and
// commits. This validates the foundation for using a watch-based (rather than
// polling) approach in waitForPolicyComputationResult.
//
// The critical scenario is:
//  1. Endpoint calls GetIdentityPolicyByIdentity (production code) which
//     internally creates a ReadTxn snapshot and calls GetWatch.
//  2. Key does NOT exist → returns a watch channel from the snapshot.
//  3. RecomputeIdentityPolicy runs (production code), creating a WriteTxn,
//     inserting the result, and committing.
//  4. The watch channel from step 2 must fire.
func TestWatchChannelFiresOnUpdate(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	t.Run("not found then created via RecomputeIdentityPolicy", func(t *testing.T) {
		_, _, computer := fixture(t)

		targetID := identity.NumericIdentity(7)

		// Use the production GetIdentityPolicyByIdentity path.
		// Key does NOT exist → we get a watch channel.
		// For a missing key, statedb returns the closest ancestor node's
		// watch channel, which may fire on ANY write in the subtree (not
		// just our target key). This is fine — the watch-based loop
		// handles spurious wake-ups by re-checking the condition.
		_, _, watch, found := computer.GetIdentityPolicyByIdentity(
			&identity.Identity{ID: targetID},
		)
		require.False(t, found, "key should not exist yet")
		require.NotNil(t, watch)

		// Use the production RecomputeIdentityPolicy to create the key.
		// This goes through the full goroutine path:
		// ComputeSelectorPolicy → WriteTxn → Insert → Commit.
		done, err := computer.RecomputeIdentityPolicy(
			&identity.Identity{ID: targetID}, 1,
		)
		require.NoError(t, err)
		<-done

		// The watch channel must fire after the key is created.
		select {
		case <-watch:
			// Success — the ReadTxn's watch channel was notified.
		case <-time.After(time.Second):
			t.Fatal("watch channel was NOT closed after key was " +
				"created by RecomputeIdentityPolicy")
		}

		// Verify the result is visible via a fresh production read.
		obj, _, _, found := computer.GetIdentityPolicyByIdentity(
			&identity.Identity{ID: targetID},
		)
		require.True(t, found)
		assert.Equal(t, targetID, obj.Identity)
	})

	t.Run("stale revision then updated", func(t *testing.T) {
		db, table, computer := fixture(t)

		targetID := identity.NumericIdentity(10)

		// Seed statedb with an initial entry at revision 1 via the
		// production RecomputeIdentityPolicy path.
		done, err := computer.RecomputeIdentityPolicy(
			&identity.Identity{ID: targetID}, 1,
		)
		require.NoError(t, err)
		<-done

		// Read the entry via the production path — should exist.
		obj, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.True(t, found)
		require.NotNil(t, watch)

		// Watch should be open.
		select {
		case <-watch:
			t.Fatal("watch channel closed before any update")
		default:
		}

		// Update the entry to a higher revision. We use a direct WriteTxn
		// here because RecomputeIdentityPolicy's revision comes from the
		// policy repo (which is 0 in tests), making it impossible to
		// simulate a revision bump through that path alone.
		// This still exercises the same statedb WriteTxn → Insert → Commit
		// path that RecomputeIdentityPolicy uses internally.
		wtxn := db.WriteTxn(table)
		_, _, err = table.Insert(wtxn, Result{Identity: targetID, Revision: obj.Revision + 1})
		require.NoError(t, err)
		wtxn.Commit()

		// Watch from the old snapshot (revision 0) must fire.
		select {
		case <-watch:
			// Success
		case <-time.After(time.Second):
			t.Fatal("watch channel not closed after revision update")
		}

		// Fresh read via production path sees the new revision.
		obj, _, _, found = computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.True(t, found)
		assert.Equal(t, uint64(1), obj.Revision)
	})

	t.Run("spurious watch from unrelated write does not return wrong identity", func(t *testing.T) {
		// Proves that when a watch channel fires due to an unrelated
		// identity's write, the subsequent re-query still only returns
		// data for the target identity — never the unrelated one.
		//
		// Scenario:
		// 1. Endpoint watches for identity 50 (not yet in statedb)
		// 2. Compute goroutine writes identity 51 (unrelated)
		// 3. Watch fires (spurious — ancestor node was cloned)
		// 4. Endpoint re-queries for identity 50 — must get found=false,
		//    NOT identity 51's data
		// 5. Compute goroutine writes identity 50
		// 6. Watch fires again
		// 7. Endpoint re-queries — gets identity 50's data
		db, table, computer := fixture(t)

		targetID := identity.NumericIdentity(50)
		unrelatedID := identity.NumericIdentity(51)

		// Step 1: Watch for target identity (not in statedb).
		_, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.False(t, found)
		require.NotNil(t, watch)

		// Step 2: Write an unrelated identity.
		wtxn := db.WriteTxn(table)
		_, _, err := table.Insert(wtxn, Result{Identity: unrelatedID, Revision: 99})
		require.NoError(t, err)
		wtxn.Commit()

		// Step 3: Watch fires (spurious — from ancestor node clone).
		select {
		case <-watch:
			// Expected — not-found watch channels fire on any subtree write.
		case <-time.After(time.Second):
			// Also acceptable — the tree structure may isolate the keys.
			// Either way, proceed to re-query.
		}

		// Step 4: Re-query for target identity. Must NOT return
		// unrelated identity's data.
		obj, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.False(t, found, "target identity should still not exist")

		// Even if the watch fired, the keyed lookup must not return
		// identity 51's result when we asked for identity 50.
		if found {
			require.Equal(t, targetID, obj.Identity,
				"got data for identity %d when querying for identity %d",
				obj.Identity, targetID)
		}

		// Step 5: Now write the target identity.
		wtxn = db.WriteTxn(table)
		_, _, err = table.Insert(wtxn, Result{Identity: targetID, Revision: 5})
		require.NoError(t, err)
		wtxn.Commit()

		// Step 6: New watch fires.
		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatal("watch not closed after target identity was written")
		}

		// Step 7: Re-query returns the correct identity's data.
		obj, _, _, found = computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.True(t, found)
		assert.Equal(t, targetID, obj.Identity,
			"must return target identity, not unrelated identity")
		assert.Equal(t, uint64(5), obj.Revision)
	})

	t.Run("full watch loop with spurious wakes from concurrent writes", func(t *testing.T) {
		// End-to-end test of the proposed waitForPolicyComputationResult
		// replacement pattern with concurrent writes to other identities
		// causing spurious watch wake-ups.
		//
		// An "endpoint" goroutine watches for identity 20 at revision >= 3.
		// A "noise" goroutine continuously writes to other identities,
		// causing spurious watch wake-ups. The endpoint must:
		// - Never accept a result from a wrong identity
		// - Eventually get identity 20 at the correct revision
		db, table, computer := fixture(t)

		targetID := identity.NumericIdentity(20)
		wantedRevision := uint64(3)

		// Seed with revision 1 (stale relative to wantedRevision).
		done, err := computer.RecomputeIdentityPolicy(
			&identity.Identity{ID: targetID}, 1,
		)
		require.NoError(t, err)
		<-done

		// Launch the "endpoint" goroutine using only production read APIs.
		type loopResult struct {
			obj        Result
			found      bool
			iterations int64
		}
		resultCh := make(chan loopResult, 1)
		go func() {
			timeout := time.NewTimer(2 * time.Second)
			defer timeout.Stop()
			var iters int64
			for {
				iters++
				obj, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
				if found && obj.Revision >= wantedRevision {
					// Verify we got the RIGHT identity, not a noisy one.
					resultCh <- loopResult{obj: obj, found: true, iterations: iters}
					return
				}
				// Also verify: if found but stale, it's still our identity.
				if found {
					require.Equal(t, targetID, obj.Identity)
				}
				select {
				case <-watch:
					continue
				case <-timeout.C:
					resultCh <- loopResult{found: false, iterations: iters}
					return
				}
			}
		}()

		// "Noise" goroutine: write to other identities to cause spurious
		// watch wake-ups on the endpoint's loop.
		noiseDone := make(chan struct{})
		go func() {
			defer close(noiseDone)
			for i := identity.NumericIdentity(100); i < 110; i++ {
				wtxn := db.WriteTxn(table)
				table.Insert(wtxn, Result{Identity: i, Revision: 1})
				wtxn.Commit()
				time.Sleep(5 * time.Millisecond)
			}
		}()

		// After some noise, write the target revision.
		time.Sleep(30 * time.Millisecond)
		for _, rev := range []uint64{2, 3} {
			wtxn := db.WriteTxn(table)
			_, _, err := table.Insert(wtxn, Result{Identity: targetID, Revision: rev})
			require.NoError(t, err)
			wtxn.Commit()
			time.Sleep(5 * time.Millisecond)
		}

		// Wait for both goroutines.
		<-noiseDone

		select {
		case r := <-resultCh:
			require.True(t, r.found, "endpoint should have found the result")
			assert.Equal(t, targetID, r.obj.Identity,
				"must return target identity, not a noisy identity")
			assert.GreaterOrEqual(t, r.obj.Revision, wantedRevision)
			// The loop should have iterated more than once due to spurious
			// wake-ups from the noise goroutine.
			t.Logf("endpoint loop completed in %d iterations "+
				"(>1 means spurious wake-ups were handled correctly)", r.iterations)
		case <-time.After(2 * time.Second):
			t.Fatal("endpoint goroutine did not receive result in time")
		}
	})
}

func TestRecomputeIdentityPolicy(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())
	db, table, computer := fixture(t)
	assert.NotNil(t, db)
	assert.NotNil(t, table)

	init, err := computer.RecomputeIdentityPolicy(&identity.Identity{ID: identity.NumericIdentity(4)}, 0)
	assert.NoError(t, err)
	<-init

	ch := make(chan struct{})
	var (
		wg     sync.WaitGroup
		result Result
	)
	wg.Add(1)
	once := sync.Once{}
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			var (
				found bool
				watch <-chan struct{}
			)
			res, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(identity.NumericIdentity(1))
			if found {
				result = res
				return
			} else {
				fmt.Println("not found")
			}
			once.Do(func() { close(ch) })
			select {
			case <-ticker.C:
				fmt.Println("trying again")
			case <-watch:
			}
		}
	}()

	<-ch

	wg.Add(1)
	go func() {
		defer wg.Done()
		ch, err := computer.RecomputeIdentityPolicy(&identity.Identity{ID: identity.NumericIdentity(1)}, 0)
		assert.NoError(t, err)
		<-ch
	}()

	wg.Wait()

	assert.Equal(t, identity.NumericIdentity(1), result.Identity)
}

func fixture(t *testing.T) (*statedb.DB, statedb.RWTable[Result], PolicyRecomputer) {
	t.Helper()

	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())

	var (
		db       *statedb.DB
		table    statedb.RWTable[Result]
		computer PolicyRecomputer
	)

	h := hive.New(
		cell.Module("test", "test",
			cell.Invoke(
				func(t statedb.RWTable[Result], db_ *statedb.DB, c_ PolicyRecomputer) error {
					table = t
					db = db_
					computer = c_
					return nil
				},
			),

			cell.ProvidePrivate(func() (policy.PolicyRepository, stream.Observable[policy.PolicyCacheChange]) {
				return repo, repo.PolicyCacheObservable()
			}),
			cell.ProvidePrivate(func() identitymanager.IDManager { return idmgr }),

			cell.Provide(
				func(params Params) PolicyRecomputer {
					return NewIdentityPolicyComputer(params)
				},
			),
			cell.ProvidePrivate(NewPolicyComputationTable),
		),
	)

	if err := h.Start(logger, context.Background()); err != nil {
		t.Fatalf("failed to start hive: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(logger, context.Background()); err != nil {
			t.Fatalf("failed to stop hive: %v", err)
		}
	})

	assert.NotNil(t, db)
	assert.NotNil(t, table)
	assert.NotNil(t, computer)

	return db, table, computer
}
