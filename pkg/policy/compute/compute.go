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
	RecomputeIdentityPolicy(identity *identity.Identity) (<-chan struct{}, error)
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
			_, _ = r.RecomputeIdentityPolicy(idd)
		} else {
			r.logger.Debug("Policy recomputation skipped due to non-local identity", logfields.Identity, id)
		}
	}
}

// RecomputeIdentityPolicy recomputes the policy for a specific identity.
func (r *IdentityPolicyRecomputer) RecomputeIdentityPolicy(identity *identity.Identity) (<-chan struct{}, error) {
	r.logger.Info("Recomputing policy for identity", logfields.Identity, identity)

	ch := make(chan struct{}, 1)
	go func() {
		r.mu.Lock()

		wtxn := r.db.WriteTxn(r.tbl)

		res := Result{Identity: identity}
		res.NewPolicy, res.Revision, res.OldPolicy, res.NeedsRelease, res.Err = r.repo.ComputeSelectorPolicy(identity, 0 /* TODO: Always force? */)
		fmt.Printf("chris debug: RecomputeIdentityPolicy: %+v\n", res)
		_, _, err := r.tbl.Insert(wtxn, res)
		if err != nil {
			fmt.Printf("chris debug: RecomputeIdentityPolicy failed to write to table: err=%v %+v\n", err, res)
			r.logger.Error("Failed to write into statedb policy computation table", logfields.Error, err)
			wtxn.Abort()
		}
		wtxn.Commit()

		r.mu.Unlock()
		close(ch)
	}()

	r.logger.Info("Policy recomputation completed", logfields.Identity, identity)

	return ch, nil
}

func (r *IdentityPolicyRecomputer) LocalEndpointIdentityAdded(identity *identity.Identity) {
	r.logger.Info("Adding new identity observed to policy computer", logfields.Identity, identity)
	fmt.Printf("chris debug: LocalEndpointIdentityAdded: %+v\n", identity)
	_, _ = r.RecomputeIdentityPolicy(identity)
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
