// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"slices"

	k8sapi "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
)

// Entity specifies the class of receiver/sender endpoints that do not have
// individual identities.  Entities are used to describe "outside of cluster",
// "host", etc.
//
// +kubebuilder:validation:Enum=all;world;cluster;cluster-mesh;host;init;ingress;unmanaged;remote-node;health;none;kube-apiserver
type Entity string

const (
	// EntityAll is an entity that represents all traffic
	EntityAll Entity = "all"

	// EntityWorld is an entity that represents traffic external to
	// endpoint's cluster
	EntityWorld Entity = "world"

	// EntityWorldIPv4 is an entity that represents traffic external to
	// endpoint's cluster, specifically an IPv4 endpoint, to distinguish
	// it from IPv6 in dual-stack mode.
	EntityWorldIPv4 Entity = "world-ipv4"

	// EntityWorldIPv6 is an entity that represents traffic external to
	// endpoint's cluster, specifically an IPv6 endpoint, to distinguish
	// it from IPv4 in dual-stack mode.
	EntityWorldIPv6 Entity = "world-ipv6"

	// EntityCluster is an entity that represents traffic within the
	// endpoint's cluster, to endpoints not managed by cilium
	EntityCluster Entity = "cluster"

	// EntityClusterMesh is an entity that represents traffic within the
	// complete clustermesh
	EntityClusterMesh Entity = "cluster-mesh"

	// EntityHost is an entity that represents traffic within endpoint host
	EntityHost Entity = "host"

	// EntityInit is an entity that represents an initializing endpoint
	EntityInit Entity = "init"

	// EntityIngress is an entity that represents envoy proxy
	EntityIngress Entity = "ingress"

	// EntityUnmanaged is an entity that represents unamanaged endpoints.
	EntityUnmanaged Entity = "unmanaged"

	// EntityRemoteNode is an entity that represents all remote nodes
	EntityRemoteNode Entity = "remote-node"

	// EntityHealth is an entity that represents all health endpoints.
	EntityHealth Entity = "health"

	// EntityNone is an entity that can be selected but never exist
	EntityNone Entity = "none"

	// EntityKubeAPIServer is an entity that represents the kube-apiserver.
	EntityKubeAPIServer Entity = "kube-apiserver"
)

var (
	endpointSelectorWorld = NewESFromLabels(labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved))

	endpointSelectorWorldAggregate = NewESFromLabels(labels.NewLabel(labels.IDNameAggregateWorld, "", labels.LabelSourceReserved))

	endpointSelectorWorldIPv4 = NewESFromLabels(labels.NewLabel(labels.IDNameWorldIPv4, "", labels.LabelSourceReserved))

	endpointSelectorWorldIPv6 = NewESFromLabels(labels.NewLabel(labels.IDNameWorldIPv6, "", labels.LabelSourceReserved))

	endpointSelectorHost = NewESFromLabels(labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved))

	endpointSelectorInit = NewESFromLabels(labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved))

	endpointSelectorIngress = NewESFromLabels(labels.NewLabel(labels.IDNameIngress, "", labels.LabelSourceReserved))

	endpointSelectorRemoteNode = NewESFromLabels(labels.NewLabel(labels.IDNameRemoteNode, "", labels.LabelSourceReserved))

	endpointSelectorRemoteNodeAggregate = NewESFromLabels(labels.NewLabel(labels.IDNameAggregateRemoteNode, "", labels.LabelSourceReserved))

	endpointSelectorHealth = NewESFromLabels(labels.NewLabel(labels.IDNameHealth, "", labels.LabelSourceReserved))

	EndpointSelectorNone = NewESFromLabels(labels.NewLabel(labels.IDNameNone, "", labels.LabelSourceReserved))

	endpointSelectorUnmanaged = NewESFromLabels(labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved))

	endpointSelectorKubeAPIServer = NewESFromLabels(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer])

	endpointSelectorClusterAggregate = NewESFromLabels(labels.NewLabel(labels.IDNameAggregateCluster, "", labels.LabelSourceReserved))

	endpointSelectorClusterMeshAggregate = NewESFromLabels(labels.NewLabel(labels.IDNameAggregateClusterMesh, "", labels.LabelSourceReserved))

	// used by both cluster and cluster-mesh entities
	clusterSelectors = EndpointSelectorSlice{
		endpointSelectorHost,
		endpointSelectorRemoteNode,
		endpointSelectorInit,
		endpointSelectorIngress,
		endpointSelectorHealth,
		endpointSelectorUnmanaged,
		endpointSelectorKubeAPIServer,
		endpointSelectorClusterAggregate,
	}

	entitySelectorMapping = map[Entity]EndpointSelectorSlice{
		EntityAll:           {WildcardEndpointSelector},
		EntityWorld:         {endpointSelectorWorld, endpointSelectorWorldIPv4, endpointSelectorWorldIPv6, endpointSelectorWorldAggregate},
		EntityWorldIPv4:     {endpointSelectorWorldIPv4},
		EntityWorldIPv6:     {endpointSelectorWorldIPv6},
		EntityHost:          {endpointSelectorHost},
		EntityInit:          {endpointSelectorInit},
		EntityIngress:       {endpointSelectorIngress},
		EntityRemoteNode:    {endpointSelectorRemoteNode, endpointSelectorRemoteNodeAggregate},
		EntityHealth:        {endpointSelectorHealth},
		EntityUnmanaged:     {endpointSelectorUnmanaged},
		EntityNone:          {EndpointSelectorNone},
		EntityKubeAPIServer: {endpointSelectorKubeAPIServer},
		// The cluster selector is completed per cluster by
		// NewEntitySelectorMapping().
		EntityCluster: clusterSelectors,

		// ClusterMesh can be initialized statically, as it selects all endpoints
		// with the cluster mesh label set.
		EntityClusterMesh: append(clusterSelectors,
			endpointSelectorClusterMeshAggregate,
			NewESFromMatchRequirements(nil, []v1.LabelSelectorRequirement{{
				Key:      k8sapi.PolicyLabelCluster,
				Operator: v1.LabelSelectorOpExists,
			}})),
	}
)

// EntitySelectorMapping maps special entity names in policies to selectors.
// If you add an entity, also update the CRD validation above.
// Each mapping is scoped to a cluster so that policies from different clusters
// can be processed concurrently without sharing mutable state.
type EntitySelectorMapping struct {
	selectors map[Entity]EndpointSelectorSlice
}

// NewEntitySelectorMapping returns the entity selectors for the given cluster.
func NewEntitySelectorMapping(clusterName string) EntitySelectorMapping {
	selectors := make(map[Entity]EndpointSelectorSlice, len(entitySelectorMapping)+1)
	for entity, endpointSelectors := range entitySelectorMapping {
		selectors[entity] = slices.Clone(endpointSelectors)
	}
	selectors[EntityCluster] = append(slices.Clone(selectors[EntityCluster]),
		NewESFromLabels(labels.NewLabel(k8sapi.PolicyLabelCluster, clusterName, labels.LabelSourceK8s)),
	)
	return EntitySelectorMapping{selectors: selectors}
}

// DefaultEntitySelectorMapping returns the cluster-independent entity mapping.
// Use NewEntitySelectorMapping when resolving EntityCluster for a specific cluster.
func DefaultEntitySelectorMapping() EntitySelectorMapping {
	return EntitySelectorMapping{selectors: entitySelectorMapping}
}

// Selectors returns the endpoint selectors for entity.
func (m EntitySelectorMapping) Selectors(entity Entity) EndpointSelectorSlice {
	return slices.Clone(m.selectors[entity])
}

// HasSelector reports whether entity maps to a selector with key.
func (m EntitySelectorMapping) HasSelector(entity Entity, key string) bool {
	for _, selector := range m.selectors[entity] {
		if selector.SelectorKey() == key {
			return true
		}
	}
	return false
}

func isKnownEntity(entity Entity) bool {
	if _, ok := entitySelectorMapping[entity]; ok {
		return true
	}
	return false
}

// EntitySlice is a slice of entities
type EntitySlice []Entity

// GetAsEndpointSelectors returns the provided entity slice as a slice of
// endpoint selectors
func (s EntitySlice) GetAsEndpointSelectors(mapping EntitySelectorMapping) EndpointSelectorSlice {
	slice := EndpointSelectorSlice{}
	for _, e := range s {
		slice = append(slice, mapping.Selectors(e)...)
	}

	return slice
}
