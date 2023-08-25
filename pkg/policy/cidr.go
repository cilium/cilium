// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/policy/api"
)

// getPrefixesFromCIDR fetches all CIDRs referred to by the specified slice
// and returns them as regular golang CIDR objects.
func getPrefixesFromCIDR(cidrs api.CIDRSlice) []netip.Prefix {
	result, _, _ := ip.ParsePrefixes(cidrs.StringSlice())
	return result
}

// GetPrefixesFromCIDRSet fetches all CIDRs referred to by the specified slice
// and returns them as regular golang CIDR objects.
//
// Assumes that validation already occurred on 'rules'.
func GetPrefixesFromCIDRSet(rules api.CIDRRuleSlice) []netip.Prefix {
	cidrs := api.ComputeResultantCIDRSet(rules)
	return getPrefixesFromCIDR(cidrs)
}

// GetCIDRPrefixes runs through the specified 'rules' to find every reference
// to a CIDR in the rules, and returns a slice containing all of these CIDRs.
// Multiple rules referring to the same CIDR will result in multiple copies of
// the CIDR in the returned slice.
//
// Assumes that validation already occurred on 'rules'.
func GetCIDRPrefixes(rules api.Rules) []netip.Prefix {
	if len(rules) == 0 {
		return nil
	}
	res := make([]netip.Prefix, 0, 32)
	for _, r := range rules {
		for _, ir := range r.Ingress {
			if len(ir.FromCIDR) > 0 {
				res = append(res, getPrefixesFromCIDR(ir.FromCIDR)...)
			}
			if len(ir.FromCIDRSet) > 0 {
				res = append(res, GetPrefixesFromCIDRSet(ir.FromCIDRSet)...)
			}
		}
		for _, ir := range r.IngressDeny {
			if len(ir.FromCIDR) > 0 {
				res = append(res, getPrefixesFromCIDR(ir.FromCIDR)...)
			}
			if len(ir.FromCIDRSet) > 0 {
				res = append(res, GetPrefixesFromCIDRSet(ir.FromCIDRSet)...)
			}
		}
		for _, er := range r.Egress {
			if len(er.ToCIDR) > 0 {
				res = append(res, getPrefixesFromCIDR(er.ToCIDR)...)
			}
			if len(er.ToCIDRSet) > 0 {
				res = append(res, GetPrefixesFromCIDRSet(er.ToCIDRSet)...)
			}
		}
		for _, er := range r.EgressDeny {
			if len(er.ToCIDR) > 0 {
				res = append(res, getPrefixesFromCIDR(er.ToCIDR)...)
			}
			if len(er.ToCIDRSet) > 0 {
				res = append(res, GetPrefixesFromCIDRSet(er.ToCIDRSet)...)
			}
		}
	}
	return res
}
