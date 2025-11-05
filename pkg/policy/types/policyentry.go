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
	// Priority defines the precedence of this rule in relation to other rules.  Lower values
	// take precedence over higher values. Rules having the default priority level 0 are
	// considered first, then the rest of the rules, from the earliest to later priority levels.
	// This is currently limited to 24 bits, i.e., max allowed priority is (1<<24-1).
	Priority uint32

	// Authentication specifies the cryptographic authentication required for the traffic to be
	// allowed
	Authentication *api.Authentication

	// Log specifies custom policy-specific Hubble logging configuration.
	Log api.LogConfig

	// Subject specifies the endpoint that this rule applies to
	Subject *LabelSelector

	// L3 specifies the source/destination endpoints or all endpoints if empty
	L3 Selectors

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
