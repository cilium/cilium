// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"

	k8sapi "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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

	// EntityKubeAPIServer is an entity that represents the kube-apiserver.
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

// customizableEntities lists entities that may be extended with additional
// label selectors via the policy-entity-selectors configuration option.
var customizableEntities = map[Entity]struct{}{
	EntityWorld:         {},
	EntityWorldIPv4:     {},
	EntityWorldIPv6:     {},
	EntityHost:          {},
	EntityInit:          {},
	EntityIngress:       {},
	EntityRemoteNode:    {},
	EntityHealth:        {},
	EntityUnmanaged:     {},
	EntityNone:          {},
	EntityKubeAPIServer: {},
}

// ParseAdditionalEntitySelectors parses the policy-entity-selectors JSON
// configuration into additional endpoint selectors per entity. The selectors
// are appended to the default entity selectors at runtime.
func ParseAdditionalEntitySelectors(raw string) (map[Entity]EndpointSelectorSlice, error) {
	if raw == "" {
		return nil, nil
	}

	var parsed map[string]slim_metav1.LabelSelector
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("unable to parse policy-entity-selectors: %w", err)
	}

	result := make(map[Entity]EndpointSelectorSlice, len(parsed))
	for name, labelSelector := range parsed {
		entity := Entity(name)
		if _, ok := customizableEntities[entity]; !ok {
			return nil, fmt.Errorf("entity %q cannot be customized", name)
		}
		if len(labelSelector.MatchLabels) == 0 && len(labelSelector.MatchExpressions) == 0 {
			return nil, fmt.Errorf("entity %q requires a non-empty label selector", name)
		}

		result[entity] = append(result[entity], NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &labelSelector))
	}

	return result, nil
}

func applyAdditionalEntitySelectors(additional map[Entity]EndpointSelectorSlice) {
	for entity, selectors := range additional {
		EntitySelectorMapping[entity] = append(EntitySelectorMapping[entity], selectors...)
	}

	// kube-apiserver is also part of the cluster entity.
	if selectors, ok := additional[EntityKubeAPIServer]; ok {
		EntitySelectorMapping[EntityCluster] = append(EntitySelectorMapping[EntityCluster], selectors...)
	}
}

// InitEntities is called to initialize the policy API layer
func InitEntities(clusterName string, additional map[Entity]EndpointSelectorSlice) {
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

	applyAdditionalEntitySelectors(additional)
}
