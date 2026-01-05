// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

// RulestoPolicyEntries converts the external rule type to the internal policy entry representation.
func RulesToPolicyEntries(rules api.Rules) types.PolicyEntries {
	entries := types.PolicyEntries{}
	for _, rule := range rules {
		ls, node := getSelector(rule)

		subjectSelector := types.NewLabelSelector(ls)
		ingressDefaultDeny, egressDefaultDeny := evaluateDefaultDenyForRule(rule)

		for _, iRule := range rule.Ingress {
			l3 := mergeEndpointSelectors(
				iRule.FromEndpoints,
				iRule.FromNodes,
				iRule.FromEntities,
				iRule.FromCIDR,
				iRule.FromCIDRSet,
				nil)

			l4 := make(api.PortRules, 0, len(iRule.ToPorts)+len(iRule.ICMPs))
			l4 = append(l4, iRule.ToPorts...)
			l4 = append(l4, icmpRules(iRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:        subjectSelector,
				Node:           node,
				Labels:         rule.Labels,
				DefaultDeny:    ingressDefaultDeny,
				Deny:           false,
				Ingress:        true,
				L3:             l3,
				L4:             l4,
				Authentication: iRule.Authentication,
				Log:            rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, iRule := range rule.IngressDeny {
			l3 := mergeEndpointSelectors(
				iRule.FromEndpoints,
				iRule.FromNodes,
				iRule.FromEntities,
				iRule.FromCIDR,
				iRule.FromCIDRSet,
				nil)

			l4 := make(api.PortRules, 0, len(iRule.ToPorts)+len(iRule.ICMPs))
			l4 = append(l4, portDenyRulesToPortRules(iRule.ToPorts)...)
			l4 = append(l4, icmpRules(iRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:     subjectSelector,
				Node:        node,
				Labels:      rule.Labels,
				DefaultDeny: ingressDefaultDeny,
				Deny:        true,
				Ingress:     true,
				L3:          l3,
				L4:          l4,
				Log:         rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, eRule := range rule.Egress {
			l3 := mergeEndpointSelectors(
				eRule.ToEndpoints,
				eRule.ToNodes,
				eRule.ToEntities,
				eRule.ToCIDR,
				eRule.ToCIDRSet,
				eRule.ToFQDNs)

			l4 := make(api.PortRules, 0, len(eRule.ToPorts)+len(eRule.ICMPs))
			l4 = append(l4, eRule.ToPorts...)
			l4 = append(l4, icmpRules(eRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:        subjectSelector,
				Node:           node,
				Labels:         rule.Labels,
				DefaultDeny:    egressDefaultDeny,
				Deny:           false,
				Ingress:        false,
				L3:             l3,
				L4:             l4,
				Authentication: eRule.Authentication,
				Log:            rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, eRule := range rule.EgressDeny {
			l3 := mergeEndpointSelectors(
				eRule.ToEndpoints,
				eRule.ToNodes,
				eRule.ToEntities,
				eRule.ToCIDR,
				eRule.ToCIDRSet,
				nil)

			l4 := make(api.PortRules, 0, len(eRule.ToPorts)+len(eRule.ICMPs))
			l4 = append(l4, portDenyRulesToPortRules(eRule.ToPorts)...)
			l4 = append(l4, icmpRules(eRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:     subjectSelector,
				Node:        node,
				Labels:      rule.Labels,
				DefaultDeny: egressDefaultDeny,
				Deny:        true,
				Ingress:     false,
				L3:          l3,
				L4:          l4,
				Log:         rule.Log,
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

// getSelector returns either the endpoint selector, which is the target of a policy rule and true if the endpoint represents a node.
func getSelector(rule *api.Rule) (api.EndpointSelector, bool) {
	if es := rule.NodeSelector; es.LabelSelector != nil {
		return es, true
	}
	return rule.EndpointSelector, false
}
