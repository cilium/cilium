// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// PolicyEntry specifies the L3/L4 details of a single policy rule
//
// +deepequal-gen=true
type PolicyEntry struct {
	// Authentication specifies the cryptographic authentication required for the traffic to be allowed
	Authentication *api.Authentication

	// Log specifies custom policy-specific Hubble logging configuration.
	Log api.LogConfig

	// Subject specifies the endpoint that this rule applies to
	Subject api.EndpointSelector

	// L3 specifies the source/destination endpoints or all endpoints if empty
	L3 PeerSelectorSlice

	// L4 specifies the source/destination port rules or none if empty
	L4 api.PortRules

	// Labels stores optional metadata.
	Labels labels.LabelArray

	// DefaultDeny is true if affected subjects should have non-selected traffic denied
	DefaultDeny bool

	// Deny is true if this rule should deny traffic
	Deny bool

	// Ingress is true if rule should affect ingress traffic, false otherwise
	Ingress bool

	// Node is true if EndpointSelector refers to a node
	Node bool
}

// PolicyEntries is a slice of pointers to PolicyEntry
type PolicyEntries []*PolicyEntry

// PeerSelector is a generic representation of an endpoint selector.
type PeerSelector interface {
	IsPeerSelector()
}

// PeerSelectorSlice is a slice that can hold any of the supported selectors,
// including EndpointSelector and FQDNSelector.
type PeerSelectorSlice []PeerSelector

// DeepEqual returns true if both PeerSelectorSlices are deep equal.
// As the elements of the slice are interfaces, we have to implement
// a type switch and call DeepEqual on each possible concrete type.
func (s *PeerSelectorSlice) DeepEqual(other *PeerSelectorSlice) bool {
	if s == nil && other == nil {
		return true
	}
	if s == nil || other == nil {
		return false
	}
	if len(*s) != len(*other) {
		return false
	}

	for idx := range *s {
		p1, p2 := (*s)[idx], (*other)[idx]
		switch v1 := p1.(type) {
		case api.EndpointSelector:
			if v2, ok := p2.(api.EndpointSelector); !ok || !v1.DeepEqual(&v2) {
				return false
			}
		case api.FQDNSelector:
			if v2, ok := p2.(api.FQDNSelector); !ok || !v1.DeepEqual(&v2) {
				return false
			}
		case api.CIDR:
			if v2, ok := p2.(api.CIDR); !ok || v1 != v2 {
				return false
			}
		case api.CIDRRule:
			if v2, ok := p2.(api.CIDRRule); !ok || !v1.DeepEqual(&v2) {
				return false
			}
		default:
			return false
		}
	}

	return true
}

// GetAsEndpointSelectors returns the slice of peer selectors as a slice of endpoint selectors.
func (s PeerSelectorSlice) GetAsEndpointSelectors() api.EndpointSelectorSlice {
	res := make(api.EndpointSelectorSlice, 0, len(s))
	for idx := range s {
		switch v := s[idx].(type) {
		case api.EndpointSelector:
			res = append(res, v)
		case api.CIDR:
			res = append(res, api.CIDRSlice{v}.GetAsEndpointSelectors()...)
		case api.CIDRRule:
			res = append(res, api.CIDRRuleSlice{v}.GetAsEndpointSelectors()...)
		case api.FQDNSelector:
			// FQDN selector are excluded because they have to be handled separately
		}
	}
	return res
}

// ToPeerSelectorSlice converts a slice of any concrete type that implements PeerSelector
// into a PeerSelectorSlice.
func ToPeerSelectorSlice[T PeerSelector](source []T) PeerSelectorSlice {
	if source == nil {
		return nil
	}
	peers := make(PeerSelectorSlice, len(source))
	for k, v := range source {
		peers[k] = v
	}
	return peers
}

// FromPeerSelectorSlice takes a slice of PeerSelector and returns a new slice
// containing only the elements that match the requested concrete type T.
func FromPeerSelectorSlice[T PeerSelector](source PeerSelectorSlice) []T {
	result := make([]T, 0)
	for _, v := range source {
		if item, ok := v.(T); ok {
			result = append(result, item)
		}
	}
	return result
}
