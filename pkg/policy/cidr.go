// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"

	"k8s.io/apimachinery/pkg/util/sets"
)

// getPrefixesFromCIDR fetches all CIDRs referred to by the specified slice
// and returns them as regular golang CIDR objects.
func getPrefixesFromCIDR(cidrs api.CIDRSlice) []netip.Prefix {
	result, _, _ := ip.ParsePrefixes(cidrs.StringSlice())
	return result
}

// getPrefixesFromCIDRSet fetches all CIDRs referred to by the specified slice
// and returns them as regular golang CIDR objects. Includes CIDRs listed in
// ExceptCIDRs fields.
//
// Assumes that validation already occurred on 'rules'.
func getPrefixesFromCIDRSet(rules api.CIDRRuleSlice) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(rules))
	for _, rule := range rules {
		if rule.Cidr != "" {
			pfx, err := netip.ParsePrefix(string(rule.Cidr))
			if err == nil {
				// must parse, was already validated.
				out = append(out, pfx.Masked())
			}
		}
		for _, except := range rule.ExceptCIDRs {
			pfx, err := netip.ParsePrefix(string(except))
			if err == nil {
				out = append(out, pfx.Masked())
			}
		}
	}

	return out
}

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
		cidrs := types.FromPeerSelectorSlice[api.CIDR](r.L3)
		res.Insert(getPrefixesFromCIDR(cidrs)...)
		cidrRules := types.FromPeerSelectorSlice[api.CIDRRule](r.L3)
		res.Insert(getPrefixesFromCIDRSet(cidrRules)...)
	}
	return res.UnsortedList()
}
