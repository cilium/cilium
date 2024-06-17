// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	k8sapi "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

// Entity specifies the class of receiver/sender endpoints that do not have
// individual identities.  Entities are used to describe "outside of cluster",
// "host", etc.
//
// +kubebuilder:validation:Enum=all;world;cluster;host;init;ingress;unmanaged;remote-node;health;none;kube-apiserver
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

	// EntityNone is an entity that represents the kube-apiserver.
	EntityKubeAPIServer Entity = "kube-apiserver"
)

var (
	endpointSelectorWorld = NewESFromLabels(labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved))

	endpointSelectorWorldIPv4 = NewESFromLabels(labels.NewLabel(labels.IDNameWorldIPv4, "", labels.LabelSourceReserved))

	endpointSelectorWorldIPv6 = NewESFromLabels(labels.NewLabel(labels.IDNameWorldIPv6, "", labels.LabelSourceReserved))

	endpointSelectorHost = NewESFromLabels(labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved))

	endpointSelectorInit = NewESFromLabels(labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved))

	endpointSelectorIngress = NewESFromLabels(labels.NewLabel(labels.IDNameIngress, "", labels.LabelSourceReserved))

	endpointSelectorRemoteNode = NewESFromLabels(labels.NewLabel(labels.IDNameRemoteNode, "", labels.LabelSourceReserved))

	endpointSelectorHealth = NewESFromLabels(labels.NewLabel(labels.IDNameHealth, "", labels.LabelSourceReserved))

	EndpointSelectorNone = NewESFromLabels(labels.NewLabel(labels.IDNameNone, "", labels.LabelSourceReserved))

	endpointSelectorUnmanaged = NewESFromLabels(labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved))

	endpointSelectorKubeAPIServer = NewESFromLabels(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer])

	// EntitySelectorMapping maps special entity names that come in
	// policies to selectors
	// If you add an entry here, you must also update the CRD
	// validation above.
	EntitySelectorMapping = map[Entity]EndpointSelectorSlice{
		EntityAll:           {WildcardEndpointSelector},
		EntityWorld:         {endpointSelectorWorld, endpointSelectorWorldIPv4, endpointSelectorWorldIPv6},
		EntityWorldIPv4:     {endpointSelectorWorldIPv4},
		EntityWorldIPv6:     {endpointSelectorWorldIPv6},
		EntityHost:          {endpointSelectorHost},
		EntityInit:          {endpointSelectorInit},
		EntityIngress:       {endpointSelectorIngress},
		EntityRemoteNode:    {endpointSelectorRemoteNode},
		EntityHealth:        {endpointSelectorHealth},
		EntityUnmanaged:     {endpointSelectorUnmanaged},
		EntityNone:          {EndpointSelectorNone},
		EntityKubeAPIServer: {endpointSelectorKubeAPIServer},

		// EntityCluster is populated with an empty entry to allow the
		// cilium client importing this package to perform basic rule
		// validation. The basic rule validation only enforces
		// awareness of individual entity names and does not require
		// understanding of the individual endpoint selectors. The
		// endpoint selector for the cluster entity can only be
		// initialized at runtime as it depends on user configuration
		// such as the cluster name. See InitEntities() below.
		EntityCluster: {},
	}
)

// EntitySlice is a slice of entities
type EntitySlice []Entity

// GetAsEndpointSelectors returns the provided entity slice as a slice of
// endpoint selectors
func (s EntitySlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	slice := EndpointSelectorSlice{}
	for _, e := range s {
		if selector, ok := EntitySelectorMapping[e]; ok {
			slice = append(slice, selector...)
		}
	}

	return slice
}

// InitEntities is called to initialize the policy API layer
func InitEntities(clusterName string) {
	EntitySelectorMapping[EntityCluster] = EndpointSelectorSlice{
		endpointSelectorHost,
		endpointSelectorRemoteNode,
		endpointSelectorInit,
		endpointSelectorIngress,
		endpointSelectorHealth,
		endpointSelectorUnmanaged,
		endpointSelectorKubeAPIServer,
		NewESFromLabels(labels.NewLabel(k8sapi.PolicyLabelCluster, clusterName, labels.LabelSourceK8s)),
	}
}
