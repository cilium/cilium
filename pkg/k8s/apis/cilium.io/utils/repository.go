// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

// RulestoPolicyEntries converts the external rule type to the internal policy entry representation.
func RulesToPolicyEntries(rules api.Rules) types.PolicyEntries {
	entries := types.PolicyEntries{}
	for _, rule := range rules {
		es, node := getSelector(rule)

		for _, iRule := range rule.Ingress {
			defaultDeny := rule.EnableDefaultDeny.Ingress == nil || *rule.EnableDefaultDeny.Ingress

			req := convertToLabelSelectorRequirementSlice(iRule.FromRequires)
			endpoints := iRule.GetSourceEndpointSelectorsWithRequirements(req)
			l3 := mergeEndpointSelectors(endpoints, iRule.FromCIDR, iRule.FromCIDRSet, nil)

			l4 := make(api.PortRules, 0, len(iRule.ToPorts)+len(iRule.ICMPs))
			l4 = append(l4, iRule.ToPorts...)
			l4 = append(l4, icmpRules(iRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:        es,
				Node:           node,
				Labels:         rule.Labels,
				DefaultDeny:    defaultDeny,
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
			defaultDeny := rule.EnableDefaultDeny.Ingress == nil || *rule.EnableDefaultDeny.Ingress

			req := convertToLabelSelectorRequirementSlice(iRule.FromRequires)
			endpoints := iRule.GetSourceEndpointSelectorsWithRequirements(req)
			l3 := mergeEndpointSelectors(endpoints, iRule.FromCIDR, iRule.FromCIDRSet, nil)

			l4 := make(api.PortRules, 0, len(iRule.ToPorts)+len(iRule.ICMPs))
			l4 = append(l4, portDenyRulesToPortRules(iRule.ToPorts)...)
			l4 = append(l4, icmpRules(iRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:     es,
				Node:        node,
				Labels:      rule.Labels,
				DefaultDeny: defaultDeny,
				Deny:        true,
				Ingress:     true,
				L3:          l3,
				L4:          l4,
				Log:         rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, eRule := range rule.Egress {
			defaultDeny := rule.EnableDefaultDeny.Egress == nil || *rule.EnableDefaultDeny.Egress

			req := convertToLabelSelectorRequirementSlice(eRule.ToRequires)
			endpoints := eRule.GetDestinationEndpointSelectorsWithRequirements(req)
			l3 := mergeEndpointSelectors(endpoints, eRule.ToCIDR, eRule.ToCIDRSet, eRule.ToFQDNs)

			l4 := make(api.PortRules, 0, len(eRule.ToPorts)+len(eRule.ICMPs))
			l4 = append(l4, eRule.ToPorts...)
			l4 = append(l4, icmpRules(eRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:        es,
				Node:           node,
				Labels:         rule.Labels,
				DefaultDeny:    defaultDeny,
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
			defaultDeny := rule.EnableDefaultDeny.Egress == nil || *rule.EnableDefaultDeny.Egress

			req := convertToLabelSelectorRequirementSlice(eRule.ToRequires)
			endpoints := eRule.GetDestinationEndpointSelectorsWithRequirements(req)
			l3 := mergeEndpointSelectors(endpoints, eRule.ToCIDR, eRule.ToCIDRSet, nil)

			l4 := make(api.PortRules, 0, len(eRule.ToPorts)+len(eRule.ICMPs))
			l4 = append(l4, portDenyRulesToPortRules(eRule.ToPorts)...)
			l4 = append(l4, icmpRules(eRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Subject:     es,
				Node:        node,
				Labels:      rule.Labels,
				DefaultDeny: defaultDeny,
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

func mergeEndpointSelectors(endpoints api.EndpointSelectorSlice, cidrSlice api.CIDRSlice, cidrRuleSlice api.CIDRRuleSlice, fqdns api.FQDNSelectorSlice) types.PeerSelectorSlice {
	if endpoints == nil && cidrSlice == nil && cidrRuleSlice == nil && fqdns == nil {
		return nil
	}
	l3 := make(types.PeerSelectorSlice, 0, len(endpoints)+len(cidrSlice)+len(cidrRuleSlice)+len(fqdns))
	l3 = append(l3, types.ToPeerSelectorSlice(endpoints)...)
	l3 = append(l3, types.ToPeerSelectorSlice(cidrSlice)...)
	l3 = append(l3, types.ToPeerSelectorSlice(cidrRuleSlice)...)
	l3 = append(l3, types.ToPeerSelectorSlice(fqdns)...)
	return l3
}

func portDenyRulesToPortRules(portRules api.PortDenyRules) api.PortRules {
	out := make(api.PortRules, 0, len(portRules))
	for _, pr := range portRules {
		out = append(out, api.PortRule{Ports: pr.GetPortProtocols()})
	}
	return out
}

func icmpRules(icmpRules api.ICMPRules) api.PortRules {
	out := make(api.PortRules, 0, len(icmpRules))
	icmpRules.Iterate(func(p api.Ports) error {
		pr := p.GetPortRule()
		if pr != nil {
			out = append(out, *pr)
		}
		return nil
	})
	return out
}

func convertToLabelSelectorRequirementSlice(s []api.EndpointSelector) []slim_metav1.LabelSelectorRequirement {
	var requirements []slim_metav1.LabelSelectorRequirement
	for _, selector := range s {
		requirements = append(requirements, selector.ConvertToLabelSelectorRequirementSlice()...)
	}
	return requirements
}

// getSelector returns either the endpoint selector, which is the target of a policy rule and true if the endpoint represents a node.
func getSelector(rule *api.Rule) (api.EndpointSelector, bool) {
	if es := rule.NodeSelector; es.LabelSelector != nil {
		return es, true
	}
	return rule.EndpointSelector, false
}
