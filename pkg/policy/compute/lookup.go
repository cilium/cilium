// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
)

// GetAuthTypes returns the AuthTypes required by the policy between localID
// and remoteID. Returns nil if the local identity has no computed policy yet
// or if no auth is required.
func (r *IdentityPolicyComputer) GetAuthTypes(localID, remoteID identity.NumericIdentity) types.AuthTypes {
	res, _, found := r.tbl.Get(r.db.ReadTxn(), PolicyComputationByIdentity(localID))
	if !found || res.NewPolicy == nil {
		return nil
	}
	return res.NewPolicy.GetAuthTypes(remoteID)
}

// GetPolicySnapshot returns the current SelectorPolicy for every identity in
// the compute table. The returned map is a snapshot taken at a single statedb
// revision.
func (r *IdentityPolicyComputer) GetPolicySnapshot() map[identity.NumericIdentity]policy.SelectorPolicy {
	rtxn := r.db.ReadTxn()
	snapshot := make(map[identity.NumericIdentity]policy.SelectorPolicy)
	for res := range r.tbl.All(rtxn) {
		if res.NewPolicy != nil {
			snapshot[res.Identity] = res.NewPolicy
		}
	}
	return snapshot
}
