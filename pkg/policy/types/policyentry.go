// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
	Subject *LabelSelector

	// L3 specifies the source/destination endpoints or all endpoints if empty
	L3 Selectors

	// Requirements is a list of additional constraints which must be met
	// in order for the selected peer endpoints to be reachable
	Requirements []slim_metav1.LabelSelectorRequirement

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
