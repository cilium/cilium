// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
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
		for _, es := range types.FromEndpointSelectorInterfaceSlice[api.EndpointSelector](r.L3) {
			if !es.HasKeyPrefix(labels.LabelSourceCIDR) {
				continue
			}
			for _, req := range es.ConvertToLabelSelectorRequirementSlice() {
				label := labels.ParseK8sLabel(req.Key)
				if prefix, err := labels.LabelToPrefix(label.Key); err == nil {
					res.Insert(prefix)
				}
			}
		}
	}
	return res.UnsortedList()
}
