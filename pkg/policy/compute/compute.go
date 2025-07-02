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

		wtxn := r.db.WriteTxn(r.tbl)
		defer wtxn.Abort()

		res := Result{Identity: identity.ID}

		// Do we already have a given revision?
		// If so, skip calculation.
		obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(identity.ID))
		if found && obj.Revision >= toRev {
			wtxn.Commit()
			return
		}

		res.NewPolicy, res.Revision, res.OldPolicy, res.NeedsRelease, res.Err = r.repo.ComputeSelectorPolicy(identity, toRev)
		_, _, err := r.tbl.Insert(wtxn, res)
		if err != nil {
			r.logger.Error("Failed to write into statedb policy computation table", logfields.Error, err)
			return
		}
		wtxn.Commit()
	}()

	r.logger.Info(
		"Policy recomputation completed",
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

	identity := r.idmanager.Get(&event.ID)
	if identity == nil {
		return nil
	}

	if event.Kind == policy.PolicyChangeInsert {
		_, err := r.RecomputeIdentityPolicy(identity, 0)
		if err != nil {
			return err
		}
	} else if event.Kind == policy.PolicyChangeDelete {
		wtxn := r.db.WriteTxn(r.tbl)
		defer wtxn.Commit()

		obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(identity.ID))
		if !found {
			wtxn.Abort()
			return nil
		}
		_, _, err := r.tbl.Delete(wtxn, obj)
		if err != nil {
			wtxn.Abort()
			return fmt.Errorf("failed to delete from statedb policy computation table", err)
		}
	}

	return nil
}
