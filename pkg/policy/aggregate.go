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
	switch nid {
	case identity.ReservedIdentityRemoteNode, identity.ReservedIdentityKubeAPIServer:
		return identity.ReservedIdentityRemoteNode
	case identity.ReservedIdentityWorld, identity.ReservedIdentityWorldIPv4, identity.ReservedIdentityWorldIPv6:
		return identity.ReservedIdentityWorld
	case identity.ReservedIdentityCluster:
		return identity.ReservedIdentityCluster
	case identity.ReservedIdentityClusterMesh:
		return identity.ReservedIdentityClusterMesh
	case identity.IdentityUnknown:
		return identity.IdentityUnknown
	}

	// All identities below 100 are special-cased.
	// They cannot be aggregated.
	if nid < 100 {
		return identity.IdentityUnknown
	}

	switch nid.Scope() {
	case identity.IdentityScopeRemoteNode:
		return identity.ReservedIdentityRemoteNode
	case identity.IdentityScopeLocal:
		return identity.ReservedIdentityWorld
	}

	// NID is global scope and > 100.
	// Determine if nid is in-cluster.
	cid := nid.ClusterID()
	if cid == option.Config.ClusterID {
		return identity.ReservedIdentityCluster
	}
	return identity.ReservedIdentityClusterMesh
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
	identity.ReservedIdentityRemoteNode,
	identity.ReservedIdentityWorld,
	identity.ReservedIdentityCluster,
	identity.ReservedIdentityClusterMesh,
}
