// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The restore package provides data structures important to restoring
// DNS proxy rules. This package serves as a central source for these
// structures.
// Note that these are marshaled as JSON and any changes need to be compatible
// across an upgrade!
package restore

import (
	"regexp"
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

// RuleRegex is a wrapper for *regexp.Regexp so that we can define marshalers for it.
type RuleRegex struct {
	*regexp.Regexp
}

// Sort is only used for testing
// Sorts in place, but returns IPRules for convenience
func (r IPRules) Sort() IPRules {
	sort.SliceStable(r, func(i, j int) bool {
		return r[i].Re.String() < r[j].Re.String()
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
	regex, err := regexp.Compile(string(b))
	if err != nil {
		return err
	}
	r.Regexp = regex
	return nil
}

// MarshalText marshals RuleRegex as string
func (r RuleRegex) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}
	return nil, nil
}
