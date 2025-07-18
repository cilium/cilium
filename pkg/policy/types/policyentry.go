// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// PolicyEntry specifies the L3/L4 details of a single policy rule
type PolicyEntry struct {
	// DefaultDeny is true if affected subjects should have non-selected traffic denied
	DefaultDeny bool

	// Deny is true if this rule should deny traffic
	Deny bool

	// Ingress is true if rule should affect ingress traffic, false otherwise
	Ingress bool

	// EndpointSelector specifies the endpoint that this rule applies to
	EndpointSelector api.EndpointSelector

	// L3 specifies the source/destination endpoints or all endpoints if empty
	L3 EndpointSelectorInterfaceSlice

	// L4 specifies the source/destination port rules or none if empty
	L4 api.PortRules

	// Authentication specifies the cryptographic authentication required for the traffic to be allowed
	Authentication *api.Authentication

	// Labels stores optional metadata.
	Labels labels.LabelArray

	// Log specifies custom policy-specific Hubble logging configuration.
	Log api.LogConfig
}

// PolicyEntries is a slice of pointers to PolicyEntry
type PolicyEntries []*PolicyEntry

// EndpointSelectorInterface is a generic representation of an endpoint selector.
// It can be converted to an EndpointSelector or FQDNSelector.
type EndpointSelectorInterface interface {
	IsEndpointSelectorInterface()
}

// EndpointSelectorInterfaceSlice is a slice that can hold any of the supported selectors,
// including EndpointSelector and FQDNSelector.
type EndpointSelectorInterfaceSlice []EndpointSelectorInterface

// ToEndpointSelectorInterfaceSlice converts a slice of any concrete type that implements EndpointSelectorInterface
// into a EndpointSelectorInterfaceSlice.
func ToEndpointSelectorInterfaceSlice[T EndpointSelectorInterface](source []T) EndpointSelectorInterfaceSlice {
	if source == nil {
		return nil
	}
	peers := make(EndpointSelectorInterfaceSlice, len(source))
	for k, v := range source {
		peers[k] = v
	}
	return peers
}

// FromEndpointSelectorInterfaceSlice takes a slice of EndpointSelectorInterface and returns a new slice
// containing only the elements that match the requested concrete type T.
func FromEndpointSelectorInterfaceSlice[T EndpointSelectorInterface](source EndpointSelectorInterfaceSlice) []T {
	result := make([]T, 0)
	for _, v := range source {
		if item, ok := v.(T); ok {
			result = append(result, item)
		}
	}
	return result
}
