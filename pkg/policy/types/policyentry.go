// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type Tier uint8

const (
	Admin Tier = iota
	Normal
	Baseline
	numTiers // one past the lowest tier
)

type Verdict uint8

const (
	Allow Verdict = iota
	Deny
	Pass
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Pass:
		return "pass"
	default:
		return "undefined"
	}
}

// PolicyEntry specifies the L3/L4 details of a single policy rule
//
// +deepequal-gen=true
type PolicyEntry struct {
	Tier Tier

	// Priority defines the precedence of this rule in relation to other rules.  Lower values
	// take precedence over higher values. Rules having the default priority level 0 are
	// considered first, then the rest of the rules, from the earliest to later priority levels.
	Priority float64

	// Authentication specifies the cryptographic authentication required for the traffic to be
	// allowed
	Authentication *api.Authentication

	// Log specifies custom policy-specific Hubble logging configuration.
	Log api.LogConfig

	// Subject specifies the endpoint that this rule applies to
	Subject *LabelSelector

	// L3 specifies the source/destination peers.
	// Nil selects nothing.
	// Non-nil but empty L3 is implicitly treated as a wildcard selector if
	// any L4 PortRules are/ also specified.
	L3 Selectors

	// L4 specifies the source/destination port rules or none if empty
	L4 api.PortRules

	// Labels stores optional metadata.
	Labels labels.LabelArray

	// DefaultDeny is true if affected subjects should have non-selected traffic denied
	DefaultDeny bool

	// Verdict is true if this rule should deny traffic
	Verdict Verdict

	// Ingress is true if rule should affect ingress traffic, false otherwise
	Ingress bool

	// Node is true if Subject refers to a node
	Node bool
}

func (entry *PolicyEntry) IsDeny() bool {
	return entry.Verdict == Deny
}

func (entry *PolicyEntry) IsAllow() bool {
	return entry.Verdict == Allow
}

// PolicyEntries is a slice of pointers to PolicyEntry
type PolicyEntries []*PolicyEntry
