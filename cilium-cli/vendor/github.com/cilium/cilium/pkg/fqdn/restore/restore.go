// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The restore package provides data structures important to restoring
// DNS proxy rules. This package serves as a central source for these
// structures.
// Note that these are marshaled as JSON and any changes need to be compatible
// across an upgrade!
package restore

import (
	"sort"
)

// DNSRules contains IP-based DNS rules for a set of ports (e.g., 53)
type DNSRules map[uint16]IPRules

// IPRules is an unsorted collection of IPrules
type IPRules []IPRule

// IPRule stores the allowed destination IPs for a DNS names matching a regex
type IPRule struct {
	Re  RuleRegex
	IPs map[string]struct{} // IPs, nil set is wildcard and allows all IPs!
}

// RuleRegex is a wrapper for a pointer to a string so that we can define marshalers for it.
type RuleRegex struct {
	Pattern *string
}

// Sort is only used for testing
// Sorts in place, but returns IPRules for convenience
func (r IPRules) Sort() IPRules {
	sort.SliceStable(r, func(i, j int) bool {
		if r[i].Re.Pattern != nil && r[j].Re.Pattern != nil {
			return *r[i].Re.Pattern < *r[j].Re.Pattern
		}
		if r[i].Re.Pattern != nil {
			return true
		}
		return false
	})

	return r
}

// Sort is only used for testing
// Sorts in place, but returns DNSRules for convenience
func (r DNSRules) Sort() DNSRules {
	for port, ipRules := range r {
		if len(ipRules) > 0 {
			ipRules = ipRules.Sort()
			r[port] = ipRules
		}
	}
	return r
}

// UnmarshalText unmarshals json into a RuleRegex
// This must have a pointer receiver, otherwise the RuleRegex remains empty.
func (r *RuleRegex) UnmarshalText(b []byte) error {
	pattern := string(b)
	r.Pattern = &pattern
	return nil
}

// MarshalText marshals RuleRegex as string
func (r RuleRegex) MarshalText() ([]byte, error) {
	if r.Pattern != nil {
		return []byte(*r.Pattern), nil
	}
	return nil, nil
}
