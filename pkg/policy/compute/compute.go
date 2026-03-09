// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"fmt"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

type PolicyRecomputer interface {
	RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error)
	RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error)
	UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], fromRev, toRev uint64)
	GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool)
}

type Result struct {
	Identity             identity.NumericIdentity
	NewPolicy, OldPolicy policy.SelectorPolicy
	Revision             uint64
	NeedsRelease         bool
	Err                  error
}

func (r *IdentityPolicyComputer) UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], _, toRev uint64) {
	for id := range idsToRegen.Members() {
		if idd := r.idmanager.Get(&id); idd != nil {
			_, _ = r.RecomputeIdentityPolicy(idd, toRev)
		} else {
			r.logger.Debug("Policy recomputation skipped due to non-local identity", logfields.Identity, id)
		}
	}
}

// RecomputeIdentityPolicy recomputes the policy for a specific identity.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error) {
	r.logger.Info(
		"Recomputing policy for identity",
		logfields.Identity, identity,
		logfields.PolicyRevision, toRev,
	)

	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)

		res := Result{Identity: identity.ID}

		// Check if we already have this revision using a ReadTxn so we
		// don't hold the table lock during the (potentially expensive)
		// policy computation below.
		obj, _, found := r.tbl.Get(r.db.ReadTxn(), PolicyComputationByIdentity(identity.ID))
		if found && obj.Revision >= toRev {
			return
		}

		// Compute policy without holding any transaction. This can be
		// expensive for policies that read Kubernetes secrets (TLS).
		res.NewPolicy, res.Revision, res.OldPolicy, res.NeedsRelease, res.Err = r.repo.ComputeSelectorPolicy(identity, toRev)

		// Acquire WriteTxn only for the insert so the statedb watch
		// channel fires promptly, unblocking endpoint regeneration.
		wtxn := r.db.WriteTxn(r.tbl)
		// Re-check: don't regress if a newer revision was committed
		// while we were computing.
		obj, _, found = r.tbl.Get(wtxn, PolicyComputationByIdentity(identity.ID))
		if found && obj.Revision >= res.Revision {
			wtxn.Abort()
			return
		}
		_, _, err := r.tbl.Insert(wtxn, res)
		if err != nil {
			wtxn.Abort()
			r.logger.Error("Failed to write into statedb policy computation table",
				logfields.Error, err,
				logfields.Identity, identity.ID,
				logfields.PolicyRevision, toRev,
			)
			return
		}
		wtxn.Commit()

		r.logger.Info(
			"Policy recomputation completed",
			logfields.Identity, identity,
			logfields.PolicyRevision, toRev,
		)

		if res.OldPolicy != nil && res.NeedsRelease {
			res.OldPolicy.MaybeDetach()
		}
	}()

	r.logger.Info(
		"Policy recomputation scheduled",
		logfields.Identity, identity,
		logfields.PolicyRevision, toRev,
	)

	return ch, nil
}

// RecomputeIdentityPolicy recomputes the policy for a specific identity.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error) {
	ws := statedb.NewWatchSet()

	r.logger.Info("Recomputing policy for all identities")
	for _, id := range r.idmanager.GetAll() {
		if ch, err := r.RecomputeIdentityPolicy(id, toRev); err != nil {
			return nil, err
		} else {
			ws.Add(ch)
		}
	}
	return ws, nil
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool) {
	return r.tbl.GetWatch(r.db.ReadTxn(), PolicyComputationByIdentity(identity))
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool) {
	if identity == nil {
		return Result{}, 0, nil, false
	}
	return r.GetIdentityPolicyByNumericIdentity(identity.ID)
}

func (r *IdentityPolicyComputer) handlePolicyCacheEvent(ctx context.Context, event policy.PolicyCacheChange) error {
	r.logger.Debug("Handle policy cache event", logfields.Identity, event.ID)

	// Handle DELETE first — the identity may already be removed from the manager
	// by the time we process this event, but we still need to clean up statedb.
	if event.Kind == policy.PolicyChangeDelete {
		wtxn := r.db.WriteTxn(r.tbl)
		obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(event.ID))
		if !found {
			wtxn.Abort()
			return nil
		}
		_, _, err := r.tbl.Delete(wtxn, obj)
		if err != nil {
			wtxn.Abort()
			return fmt.Errorf("failed to delete from statedb policy computation table: %w", err)
		}
		wtxn.Commit()
		return nil
	}

	identity := r.idmanager.Get(&event.ID)
	if identity == nil {
		return nil
	}

	if event.Kind == policy.PolicyChangeInsert {
		_, err := r.RecomputeIdentityPolicy(identity, 0)
		if err != nil {
			return err
		}
	}
	return nil
}
