// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func TestRecomputeIdentityPolicy(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	t.Run("creates entry and fires waiting watch", func(t *testing.T) {
		_, _, computer, idmgr := fixture(t)

		targetID := identity.NumericIdentity(7)
		id := identity.NewIdentity(targetID, labels.Labels{})
		idmgr.Add(id)

		_, _, watch, found := computer.GetIdentityPolicyByIdentity(id)
		require.False(t, found)
		require.NotNil(t, watch)

		done, err := computer.RecomputeIdentityPolicy(id, 1)
		require.NoError(t, err)
		<-done

		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatal("watch channel not closed after key creation")
		}

		obj, _, _, found := computer.GetIdentityPolicyByIdentity(id)
		require.True(t, found)
		assert.Equal(t, targetID, obj.Identity)
	})

	t.Run("update fires watch", func(t *testing.T) {
		db, table, computer, idmgr := fixture(t)

		targetID := identity.NumericIdentity(10)
		id := identity.NewIdentity(targetID, labels.Labels{})
		idmgr.Add(id)

		done, err := computer.RecomputeIdentityPolicy(id, 1)
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

		wtxn := db.WriteTxn(table)
		_, _, err = table.Insert(wtxn, Result{Identity: targetID, Revision: obj.Revision + 1})
		require.NoError(t, err)
		wtxn.Commit()

		select {
		case <-watch:
		case <-time.After(time.Second):
			t.Fatal("watch channel not closed after revision update")
		}

		newObj, _, _, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
		require.True(t, found)
		assert.Equal(t, obj.Revision+1, newObj.Revision)
	})

	t.Run("watch loop converges to target revision", func(t *testing.T) {
		db, table, computer, idmgr := fixture(t)

		targetID := identity.NumericIdentity(20)
		id := identity.NewIdentity(targetID, labels.Labels{})
		idmgr.Add(id)

		done, err := computer.RecomputeIdentityPolicy(id, 1)
		require.NoError(t, err)
		<-done

		const wantedRevision = uint64(3)

		// Write unrelated entries.
		go func() {
			for i := identity.NumericIdentity(100); i < 110; i++ {
				wtxn := db.WriteTxn(table)
				table.Insert(wtxn, Result{Identity: i, Revision: 1})
				wtxn.Commit()
			}
			for _, rev := range []uint64{2, 3} {
				wtxn := db.WriteTxn(table)
				_, _, err := table.Insert(wtxn, Result{Identity: targetID, Revision: rev})
				require.NoError(t, err)
				wtxn.Commit()
			}
		}()

		// Loop until the watch returns the target we want.
		deadline := time.After(2 * time.Second)
		for {
			obj, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(targetID)
			if found && obj.Revision >= wantedRevision {
				assert.Equal(t, targetID, obj.Identity)
				return
			}
			if found {
				require.Equal(t, targetID, obj.Identity)
			}
			select {
			case <-watch:
			case <-deadline:
				t.Fatal("did not converge to wantedRevision in time")
			}
		}
	})
}

func fixture(t *testing.T) (*statedb.DB, statedb.RWTable[Result], PolicyRecomputer, identitymanager.IDManager) {
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

	return db, table, computer, idmgr
}
