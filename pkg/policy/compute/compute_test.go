// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
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

// TestWatchChannelFiresOnUpdate verifies statedb watch channels fire correctly
// when entries are created or updated via the production code paths.
func TestWatchChannelFiresOnUpdate(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	t.Run("not found then created", func(t *testing.T) {
		_, _, computer := fixture(t)

		targetID := identity.NumericIdentity(7)

		_, _, watch, found := computer.GetIdentityPolicyByIdentity(
			&identity.Identity{ID: targetID},
		)
		require.False(t, found)
		require.NotNil(t, watch)

		done, err := computer.RecomputeIdentityPolicy(
			&identity.Identity{ID: targetID}, 1,
		)
		require.NoError(t, err)
		<-done

		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatal("watch channel not closed after key creation")
		}

		obj, _, _, found := computer.GetIdentityPolicyByIdentity(
			&identity.Identity{ID: targetID},
		)
		require.True(t, found)
		assert.Equal(t, targetID, obj.Identity)
	})

	t.Run("stale revision then updated", func(t *testing.T) {
		db, table, computer := fixture(t)

		targetID := identity.NumericIdentity(10)

		done, err := computer.RecomputeIdentityPolicy(
			&identity.Identity{ID: targetID}, 1,
		)
		require.NoError(t, err)
		<-done

		obj, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.True(t, found)
		require.NotNil(t, watch)

		select {
		case <-watch:
			t.Fatal("watch channel closed before any update")
		default:
		}

		// Direct WriteTxn because RecomputeIdentityPolicy can't bump revision
		// without a real repo (revision always comes from the repo, which is 0 in tests).
		wtxn := db.WriteTxn(table)
		_, _, err = table.Insert(wtxn, Result{Identity: targetID, Revision: obj.Revision + 1})
		require.NoError(t, err)
		wtxn.Commit()

		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatal("watch channel not closed after revision update")
		}

		obj, _, _, found = computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.True(t, found)
		assert.Equal(t, uint64(1), obj.Revision)
	})

	t.Run("watch loop with spurious wakes from concurrent writes", func(t *testing.T) {
		// Concurrent writes to unrelated identities cause spurious watch
		// wake-ups. The loop must never accept a wrong identity's data.
		db, table, computer := fixture(t)

		targetID := identity.NumericIdentity(20)
		wantedRevision := uint64(3)

		done, err := computer.RecomputeIdentityPolicy(
			&identity.Identity{ID: targetID}, 1,
		)
		require.NoError(t, err)
		<-done

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
					resultCh <- loopResult{obj: obj, found: true, iterations: iters}
					return
				}
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

		time.Sleep(30 * time.Millisecond)
		for _, rev := range []uint64{2, 3} {
			wtxn := db.WriteTxn(table)
			_, _, err := table.Insert(wtxn, Result{Identity: targetID, Revision: rev})
			require.NoError(t, err)
			wtxn.Commit()
			time.Sleep(5 * time.Millisecond)
		}

		<-noiseDone

		select {
		case r := <-resultCh:
			require.True(t, r.found)
			assert.Equal(t, targetID, r.obj.Identity)
			assert.GreaterOrEqual(t, r.obj.Revision, wantedRevision)
			t.Logf("loop completed in %d iterations", r.iterations)
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
			}
			once.Do(func() { close(ch) })
			select {
			case <-ticker.C:
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
