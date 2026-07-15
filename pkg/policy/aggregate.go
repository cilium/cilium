// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The policy subsystem supports a limit mode of aggregating identities in to
// semantic buckets. This is done based on logical aggregation rather than
// masks (i.e. like a router).
//
// When determining the policy verdict for a given flow, the datapath will perform
// two lookups: one with the specific identity, and one with the aggregated identity.
// Whichever has higher precedence will be selected.
//
// This file has the user-space logic for implementing identity aggregation.
//
// An identity is a "leaf" if its aggregate is not the same as itself.
// Otherwise, it is an aggregate.
//
// When generating the policy map, we need to manage the fact that not all
// identities aggregate to 0. To do this, entries with ID 0 are expanded
// to include all aggregates.
//
// The aggregate identities do not have the "logical" set of labels applied
// to them. For example, the world aggregate identity does not have the `reserved:world`
// label attached. This is to prevent over-selection in the case of NotIn
// selectors (i.e. hole-punching).
//
// Consider the selector "reserved:world !cidr:1.1.1.1/32". If `reserved:world` / 2
// were the aggregate ID, then traffic to `1.1.1.1/32` would be inadvertently allowed.
//
// Thus, we must instead associate the aggregate IDs with known-safe selectors
// that we are certain select the entire logical "space". At present, those are
// the entities. Otherwise, the aggregate selectors must not be selectable by
// user selectors.

package policy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

// aggregateFor returns the numeric identity that aggregates the
// given nid. If the supplied `nid` is already a wildcard,
// then it returns itself.
//
// THIS MUST!!! MATCH THE IMPLEMENTATION in bpf/lib/identity.h
func aggregateFor(nid identity.NumericIdentity) identity.NumericIdentity {
	// all aggregates must aggregate to themselves
	switch nid {
	case identity.IdentityUnknown, identity.ReservedIdentityAggregateCluster, identity.ReservedIdentityAggregateClusterMesh, identity.ReservedIdentityAggregateWorld, identity.ReservedIdentityAggregateRemoteNode:
		return nid
	}

	// All identities below 100 are special-cased.
	// They cannot be aggregated.
	if nid < 100 {
		return identity.IdentityUnknown
	}

	switch nid.Scope() {
	case identity.IdentityScopeRemoteNode:
		return identity.ReservedIdentityAggregateRemoteNode
	case identity.IdentityScopeLocal:
		return identity.ReservedIdentityAggregateWorld
	}

	// NID is global scope and > 100.
	// Determine if nid is in-cluster.
	cid := nid.ClusterID()
	if cid == option.Config.ClusterID {
		return identity.ReservedIdentityAggregateCluster
	}
	return identity.ReservedIdentityAggregateClusterMesh
}

// aggregates returns true if child is a child of the wildcard.
func aggregates(agg, child identity.NumericIdentity) bool {
	return agg != child && aggregateFor(child) == agg
}

// isAggregate returns true if th
func isAggregate(nid identity.NumericIdentity) bool {
	return nid == aggregateFor(nid)
}

// AllAggregates is the list of all identities that do not aggregate further.
//
// They must be inserted whenever a full wildcard (i.e. identity 0) is referenced.
var AllAggregates = []identity.NumericIdentity{
	identity.IdentityUnknown,
	identity.ReservedIdentityAggregateRemoteNode,
	identity.ReservedIdentityAggregateWorld,
	identity.ReservedIdentityAggregateCluster,
	identity.ReservedIdentityAggregateClusterMesh,
}
