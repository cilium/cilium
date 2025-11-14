// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/policy/types"

	"k8s.io/apimachinery/pkg/util/sets"
)

// GetCIDRPrefixes runs through the specified 'rules' to find every reference
// to a CIDR in the rules, and returns a slice containing all of these CIDRs.
//
// Includes prefixes referenced solely by "ExceptCIDRs" entries.
//
// Assumes that validation already occurred on 'rules'.
func GetCIDRPrefixes(rules types.PolicyEntries) []netip.Prefix {
	if len(rules) == 0 {
		return nil
	}
	res := make(sets.Set[netip.Prefix], 32)
	for _, r := range rules {
		for _, p := range r.L3 {
			prefixes := p.GetCIDRPrefixes()
			if len(prefixes) > 0 {
				res.Insert(prefixes...)
			}
		}
	}
	if res.Len() == 0 {
		return nil
	}
	return res.UnsortedList()
}
