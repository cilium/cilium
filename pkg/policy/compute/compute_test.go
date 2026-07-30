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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
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
		_, _, computer, _ := fixture(t)

		targetID := identity.NumericIdentity(7)
		id := identity.NewIdentity(targetID, labels.Labels{})

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

func TestIdentityManagerObserver(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	t.Run("add triggers implicit recompute", func(t *testing.T) {
		_, _, computer, idmgr := fixture(t)

		targetID := identity.NumericIdentity(7)
		id := identity.NewIdentity(targetID, labels.Labels{})

		idmgr.Add(id)

		obj := waitForEntry(t, computer, id, true)
		assert.Equal(t, targetID, obj.Identity)
	})

	t.Run("remove deletes entry", func(t *testing.T) {
		_, _, computer, idmgr := fixture(t)

		targetID := identity.NumericIdentity(8)
		id := identity.NewIdentity(targetID, labels.Labels{})

		idmgr.Add(id)
		waitForEntry(t, computer, id, true)

		idmgr.Remove(id)
		waitForEntry(t, computer, id, false)
	})
}

func waitForEntry(t *testing.T, computer PolicyRecomputer, id *identity.Identity, want bool) Result {
	t.Helper()
	timeout := time.After(time.Second)
	for {
		obj, _, watch, found := computer.GetIdentityPolicyByIdentity(id)
		if found == want {
			return obj
		}
		select {
		case <-watch:
		case <-timeout:
			t.Fatalf("timed out waiting for entry found=%v for identity %d", want, id.ID)
		}
	}
}

// computeFor adds an identity and waits for its initial policy to be committed.
func computeFor(t *testing.T, computer PolicyRecomputer, idmgr identitymanager.IDManager, nid identity.NumericIdentity) *identity.Identity {
	t.Helper()
	id := identity.NewIdentity(nid, labels.Labels{})
	idmgr.Add(id)
	done, err := computer.RecomputeIdentityPolicy(id, 1)
	require.NoError(t, err)
	<-done
	return id
}

func TestGetAuthTypesAndSnapshot(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	_, _, computer, idmgr := fixture(t)
	id := computeFor(t, computer, idmgr, identity.NumericIdentity(42))

	require.Nil(t, computer.GetAuthTypes(id.ID, identity.NumericIdentity(99)))
	require.Contains(t, computer.GetPolicySnapshot(), id.ID)
}

func TestBulkRecompute(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	_, _, computer, idmgr := fixture(t)
	id := computeFor(t, computer, idmgr, identity.NumericIdentity(42))

	computer.UpdatePolicy(set.NewSet(id.ID), 0, 2)
	ws, err := computer.RecomputeIdentityPolicyForAllIdentities(3)
	require.NoError(t, err)
	require.NotNil(t, ws)
}

// An identity that a policy update does not select keeps its committed policy,
// but must still have its revision advanced to the update's revision. Otherwise
// an endpoint exposed after the importer snapshotted the endpoint list has no
// way to tell that its policy is already current, and realizes a pre-import
// revision until the next unrelated update or periodic regeneration.
func TestUpdatePolicyAdvancesUnaffectedIdentities(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	_, _, computer, idmgr := fixture(t)

	affected := computeFor(t, computer, idmgr, identity.NumericIdentity(51))
	unaffected := computeFor(t, computer, idmgr, identity.NumericIdentity(52))

	// The importer passes the repository revision the update started from,
	// which is the revision the committed policies are current at.
	before, _, _, found := computer.GetIdentityPolicyByIdentity(unaffected)
	require.True(t, found)
	fromRev := before.CurrentAtRevision
	toRev := fromRev + 1

	computer.UpdatePolicy(set.NewSet(affected.ID), fromRev, toRev)

	// The unaffected identity is not recomputed, so only the advance can mark
	// it current at toRev.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		obj, _, _, found := computer.GetIdentityPolicyByIdentity(unaffected)
		assert.True(c, found)
		assert.GreaterOrEqual(c, obj.CurrentAtRevision, toRev)
	}, time.Second, time.Millisecond, "unaffected identity never became current at revision %d", toRev)

	// It must be marked current without being recomputed: the committed policy
	// is still the very same object.
	obj, _, _, found := computer.GetIdentityPolicyByIdentity(unaffected)
	require.True(t, found)
	require.NotNil(t, obj.NewPolicy)
	require.Same(t, before.NewPolicy, obj.NewPolicy,
		"unaffected identity was recomputed, not just advanced")
	// An advance must leave the revision it was computed at alone.
	require.Equal(t, before.Revision, obj.Revision)
}

// Carrying a policy forward must never satisfy a request to recompute it.
//
// Revision (computed-at) is what processRequests uses to decide whether a
// requested computation has already run. CurrentAtRevision is only a statement
// about the committed policy still being valid, so deciding on it instead would
// close a request that no computation ever served, leaving the policy stale with
// nothing left to re-trigger it.
func TestAdvanceDoesNotSatisfyRecompute(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	_, _, computer, idmgr := fixture(t)

	carried := computeFor(t, computer, idmgr, identity.NumericIdentity(71))
	other := computeFor(t, computer, idmgr, identity.NumericIdentity(72))

	before, _, _, found := computer.GetIdentityPolicyByIdentity(carried)
	require.True(t, found)
	base := before.CurrentAtRevision

	// Carry `carried` forward without recomputing it.
	toRev := base + 1
	computer.UpdatePolicy(set.NewSet(other.ID), base, toRev)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		obj, _, _, found := computer.GetIdentityPolicyByIdentity(carried)
		assert.True(c, found)
		assert.Equal(c, toRev, obj.CurrentAtRevision)
	}, time.Second, time.Millisecond)

	// Now ask for a recomputation at the revision it was carried forward to. A
	// computation must actually run, even though CurrentAtRevision already
	// reports that revision.
	done, err := computer.RecomputeIdentityPolicy(carried, toRev)
	require.NoError(t, err)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recomputation request never completed")
	}

	// OldPolicy is only set when a computation ran and replaced a committed
	// policy, so it is the oracle for "this was recomputed, not carried".
	obj, _, _, found := computer.GetIdentityPolicyByIdentity(carried)
	require.True(t, found)
	require.NotNil(t, obj.OldPolicy,
		"requested recomputation was skipped because the policy had been carried forward")
	require.GreaterOrEqual(t, obj.Revision, before.Revision)
}

// A late-delivered update for an older revision range must not drag an
// identity's revision backwards.
func TestUpdatePolicyAdvanceDoesNotRegress(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	_, _, computer, idmgr := fixture(t)

	other := computeFor(t, computer, idmgr, identity.NumericIdentity(61))
	ahead := computeFor(t, computer, idmgr, identity.NumericIdentity(62))

	before, _, _, found := computer.GetIdentityPolicyByIdentity(ahead)
	require.True(t, found)
	base := before.CurrentAtRevision

	// Carry `ahead` forward twice, then replay the first update.
	computer.UpdatePolicy(set.NewSet(other.ID), base, base+1)
	computer.UpdatePolicy(set.NewSet(other.ID), base+1, base+2)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		obj, _, _, found := computer.GetIdentityPolicyByIdentity(ahead)
		assert.True(c, found)
		assert.Equal(c, base+2, obj.CurrentAtRevision)
	}, time.Second, time.Millisecond)

	computer.UpdatePolicy(set.NewSet(other.ID), base, base+1)

	require.Never(t, func() bool {
		obj, _, _, found := computer.GetIdentityPolicyByIdentity(ahead)
		return found && obj.CurrentAtRevision < base+2
	}, 100*time.Millisecond, 10*time.Millisecond, "revision regressed below %d", base+2)
}

func fixture(t *testing.T) (*statedb.DB, statedb.RWTable[Result], PolicyRecomputer, identitymanager.IDManager) {
	t.Helper()

	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo.ID, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())

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

			cell.ProvidePrivate(func() policy.PolicyRepository { return repo }),
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
