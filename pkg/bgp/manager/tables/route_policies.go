// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

const (
	indexDelimiter = "|"
)

// DesiredRoutePolicy holds one desired BGP route policy statement with policy metadata.
// Each entry must have a unique Instance + Peer + PolicyType + Statement.Name combination.
// +deepequal-gen=true
type DesiredRoutePolicy struct {
	// Instance is BGP instance name to which this policy entry belongs.
	Instance string
	// Peer is name of the BGP peer to which this policy entry applies.
	Peer string
	// PolicyType defines type of the route policy.
	PolicyType types.RoutePolicyType
	// Statement holds desired policy statement.
	Statement *types.RoutePolicyStatement

	// Priority is used to order statements with the same Instance, Peer and PolicyType combination.
	// Lower number has higher priority (will be added to the top of the rendered policy).
	Priority int
	// Owner defines ownership of this policy entry - e.g. a reconciler name.
	Owner string
	// Resource contains the key of the resource for which this policy entry was rendered,
	// used as reconciliation helper for the owners, may be empty if not needed.
	Resource resource.Key
}

func (p *DesiredRoutePolicy) StatementName() string {
	if p == nil || p.Statement == nil {
		return ""
	}
	return p.Statement.Name
}

func (p *DesiredRoutePolicy) String() string {
	return fmt.Sprintf(
		"DesiredRoutePolicy{Instance: %s, Peer: %s, PolicyType: %s, Priority: %d, Owner: %s, Resource: %s, StatementName: %s}",
		p.Instance,
		p.Peer,
		p.PolicyType,
		p.Priority,
		p.Owner,
		p.Resource,
		p.StatementName(),
	)
}

func (*DesiredRoutePolicy) TableHeader() []string {
	return []string{
		"Instance",
		"Peer",
		"PolicyType",
		"Priority",
		"Owner",
		"Resource",
		"StatementName",
	}
}

func (p *DesiredRoutePolicy) TableRow() []string {
	return []string{
		p.Instance,
		p.Peer,
		p.PolicyType.String(),
		fmt.Sprintf("%d", p.Priority),
		p.Owner,
		p.Resource.String(),
		p.StatementName(),
	}
}

// DesiredRoutePolicyKey uniquely identifies a desired route policy statement.
type DesiredRoutePolicyKey struct {
	Instance      string
	Peer          string
	PolicyType    types.RoutePolicyType
	StatementName string
}

func (k DesiredRoutePolicyKey) Key() index.Key {
	return index.String(k.Instance + indexDelimiter + k.Peer + indexDelimiter + k.PolicyType.String() + indexDelimiter + k.StatementName)
}

func (p *DesiredRoutePolicy) GetKey() DesiredRoutePolicyKey {
	return DesiredRoutePolicyKey{
		Instance:      p.Instance,
		Peer:          p.Peer,
		PolicyType:    p.PolicyType,
		StatementName: p.StatementName(),
	}
}

type desiredRoutePolicyOwnerKey struct {
	Instance string
	Owner    string
}

func (o desiredRoutePolicyOwnerKey) Key() index.Key {
	return index.String(o.Instance + indexDelimiter + o.Owner)
}

func (p *DesiredRoutePolicy) GetOwnerKey() desiredRoutePolicyOwnerKey {
	return desiredRoutePolicyOwnerKey{
		Instance: p.Instance,
		Owner:    p.Owner,
	}
}

type desiredRoutePolicyResourceKey struct {
	Instance string
	Owner    string
	Resource resource.Key
}

func (o desiredRoutePolicyResourceKey) Key() index.Key {
	return index.String(o.Instance + indexDelimiter + o.Owner + indexDelimiter + o.Resource.String())
}

func (p *DesiredRoutePolicy) GetResourceKey() desiredRoutePolicyResourceKey {
	return desiredRoutePolicyResourceKey{
		Instance: p.Instance,
		Owner:    p.Owner,
		Resource: p.Resource,
	}
}

var (
	desiredRoutePoliciesKeyIndex = statedb.Index[*DesiredRoutePolicy, DesiredRoutePolicyKey]{
		Name: "key",
		FromObject: func(obj *DesiredRoutePolicy) index.KeySet {
			return index.NewKeySet(obj.GetKey().Key())
		},
		FromKey:    DesiredRoutePolicyKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	desiredRoutePoliciesInstanceIndex = statedb.Index[*DesiredRoutePolicy, string]{
		Name: "instance",
		FromObject: func(obj *DesiredRoutePolicy) index.KeySet {
			return index.NewKeySet(index.String(obj.Instance))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	desiredRoutePoliciesInstanceOwnerIndex = statedb.Index[*DesiredRoutePolicy, desiredRoutePolicyOwnerKey]{
		Name: "owner",
		FromObject: func(obj *DesiredRoutePolicy) index.KeySet {
			return index.NewKeySet(obj.GetOwnerKey().Key())
		},
		FromKey:    desiredRoutePolicyOwnerKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	desiredRoutePoliciesInstanceOwnerResourceIndex = statedb.Index[*DesiredRoutePolicy, desiredRoutePolicyResourceKey]{
		Name: "resource",
		FromObject: func(obj *DesiredRoutePolicy) index.KeySet {
			return index.NewKeySet(obj.GetResourceKey().Key())
		},
		FromKey:    desiredRoutePolicyResourceKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	DesiredRoutePoliciesByInstance = desiredRoutePoliciesInstanceIndex.Query
)

func DesiredRoutePoliciesByKey(key DesiredRoutePolicyKey) statedb.Query[*DesiredRoutePolicy] {
	return desiredRoutePoliciesKeyIndex.Query(key)
}

func DesiredRoutePoliciesByInstanceOwner(instance string, owner string) statedb.Query[*DesiredRoutePolicy] {
	return desiredRoutePoliciesInstanceOwnerIndex.Query(desiredRoutePolicyOwnerKey{
		Instance: instance,
		Owner:    owner,
	})
}

func DesiredRoutePoliciesByInstanceOwnerResource(instance string, owner string, resource resource.Key) statedb.Query[*DesiredRoutePolicy] {
	return desiredRoutePoliciesInstanceOwnerResourceIndex.Query(desiredRoutePolicyResourceKey{
		Instance: instance,
		Owner:    owner,
		Resource: resource,
	})
}

func NewDesiredRoutePoliciesTable(db *statedb.DB) (statedb.RWTable[*DesiredRoutePolicy], error) {
	return statedb.NewTable(
		db,
		"bgp-desired-route-policies",
		desiredRoutePoliciesKeyIndex,
		desiredRoutePoliciesInstanceIndex,
		desiredRoutePoliciesInstanceOwnerIndex,
		desiredRoutePoliciesInstanceOwnerResourceIndex,
	)
}
