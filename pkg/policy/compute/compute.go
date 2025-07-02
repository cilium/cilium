// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
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
	UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64)
	GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool)
}

type Result struct {
	Identity             *identity.Identity
	NewPolicy, OldPolicy policy.SelectorPolicy
	Revision             uint64
	NeedsRelease         bool
	Err                  error
}

// TODO: Figure out how to incorporate fromRev and toRev.
func (r *IdentityPolicyRecomputer) UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
	for id := range idsToRegen.Members() {
		if idd := r.idmanager.Get(&id); idd != nil {
			_, _ = r.RecomputeIdentityPolicy(idd, toRev)
		} else {
			r.logger.Debug("Policy recomputation skipped due to non-local identity", logfields.Identity, id)
		}
	}
}

// RecomputeIdentityPolicy recomputes the policy for a specific identity.
func (r *IdentityPolicyRecomputer) RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error) {
	r.logger.Info("Recomputing policy for identity", logfields.Identity, identity, logfields.PolicyRevision, toRev)

	ch := make(chan struct{}, 1)
	go func() {
		r.mu.Lock()

		wtxn := r.db.WriteTxn(r.tbl)
		res := Result{Identity: identity}

		var err error

		// Do we already have a given revision?
		// If so, skip calculation.
		obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(identity.ID))
		if found && obj.Revision >= toRev {
			fmt.Printf("chris debug: RecomputeIdentityPolicy already found updated policy computation: %+v\n", obj)
			goto out
		}

		res.NewPolicy, res.Revision, res.OldPolicy, res.NeedsRelease, res.Err = r.repo.ComputeSelectorPolicy(identity, toRev)
		fmt.Printf("chris debug: RecomputeIdentityPolicy: %+v\n", res)
		_, _, err = r.tbl.Insert(wtxn, res)
		if err != nil {
			fmt.Printf("chris debug: RecomputeIdentityPolicy failed to write to table: err=%v %+v\n", err, res)
			r.logger.Error("Failed to write into statedb policy computation table", logfields.Error, err)
			wtxn.Abort()
		}

	out:
		wtxn.Commit()
		r.mu.Unlock()
		close(ch)
	}()

	r.logger.Info("Policy recomputation completed", logfields.Identity, identity, logfields.PolicyRevision, toRev)

	return ch, nil
}

// RecomputeIdentityPolicy recomputes the policy for a specific identity.
func (r *IdentityPolicyRecomputer) RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error) {
	ws := statedb.NewWatchSet()

	fmt.Printf("chris debug: RecomputeIdentityPolicyForAllIdentities toRev=%v\n", toRev)
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

func (r *IdentityPolicyRecomputer) LocalEndpointIdentityAdded(identity *identity.Identity) {
	r.logger.Info("Adding new identity observed to policy computer", logfields.Identity, identity)
	fmt.Printf("chris debug: LocalEndpointIdentityAdded: %+v\n", identity)
	_, _ = r.RecomputeIdentityPolicy(identity, 0)
}

func (r *IdentityPolicyRecomputer) LocalEndpointIdentityRemoved(identity *identity.Identity) {
	r.logger.Info("Removing identity policy from policy computer", logfields.Identity, identity)

	r.mu.Lock()
	defer r.mu.Unlock()

	wtxn := r.db.WriteTxn(r.tbl)
	defer wtxn.Commit()

	obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(identity.ID))
	if !found {
		fmt.Printf("chris debug: LocalEndpointIdentityRemoved not found: %+v\n", identity)
		return
	}
	_, _, err := r.tbl.Delete(wtxn, obj)
	if err != nil {
		fmt.Printf("chris debug: LocalEndpointIdentityRemoved failed with %v: %+v\n", err, identity)
		r.logger.Error("Failed to delete from statedb policy computation table", logfields.Error, err)
	}
	fmt.Printf("chris debug: LocalEndpointIdentityRemoved removed: %+v\n", identity)
}

func (r *IdentityPolicyRecomputer) GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fmt.Printf("chris debug: GetIdentityPolicyByNumericIdentity: %+v\n", identity)
	return r.tbl.GetWatch(r.db.ReadTxn(), PolicyComputationByIdentity(identity))
}

func (r *IdentityPolicyRecomputer) GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool) {
	fmt.Printf("chris debug: GetIdentityPolicyByIdentity: %+v\n", identity)
	if identity == nil {
		fmt.Printf("chris debug: GetIdentityPolicyByIdentity identity is nil???: %+v\n", identity)
		return Result{}, 0, nil, false
	}
	return r.GetIdentityPolicyByNumericIdentity(identity.ID)
}
