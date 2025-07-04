// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

// RulesToPolicyEntries converts a slice of api.Rules to PolicyEntries
func RulesToPolicyEntries(rules api.Rules) types.PolicyEntries {
	entries := types.PolicyEntries{}
	for _, rule := range rules {
		es := getSelector(rule)

		for _, iRule := range rule.Ingress {
			defaultDeny := rule.EnableDefaultDeny.Ingress != nil && *rule.EnableDefaultDeny.Ingress
			req := convertToLabelSelectorRequirementSlice(iRule.FromRequires)
			l3 := types.ToEndpointSelectorInterfaceSlice(iRule.GetSourceEndpointSelectorsWithRequirements(req))
			l4 := append(iRule.ToPorts, icmpRules(iRule.ICMPs)...)
			entry := &types.PolicyEntry{
				EndpointSelector: es,
				Labels:           rule.Labels,
				DefaultDeny:      defaultDeny,
				Deny:             false,
				Ingress:          true,
				L3:               l3,
				L4:               l4,
				Authentication:   iRule.Authentication,
				Log:              rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, iRule := range rule.IngressDeny {
			defaultDeny := rule.EnableDefaultDeny.Ingress != nil && *rule.EnableDefaultDeny.Ingress
			req := convertToLabelSelectorRequirementSlice(iRule.FromRequires)
			l3 := types.ToEndpointSelectorInterfaceSlice(iRule.GetSourceEndpointSelectorsWithRequirements(req))
			l4 := append(portDenyRulesToPortRules(iRule.ToPorts), icmpRules(iRule.ICMPs)...)
			entry := &types.PolicyEntry{
				EndpointSelector: es,
				Labels:           rule.Labels,
				DefaultDeny:      defaultDeny,
				Deny:             true,
				Ingress:          true,
				L3:               l3,
				L4:               l4,
				Log:              rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, eRule := range rule.Egress {
			defaultDeny := rule.EnableDefaultDeny.Egress != nil && *rule.EnableDefaultDeny.Egress
			req := convertToLabelSelectorRequirementSlice(eRule.ToRequires)
			l3 := types.ToEndpointSelectorInterfaceSlice(eRule.GetDestinationEndpointSelectorsWithRequirements(req))
			l3 = append(l3, types.ToEndpointSelectorInterfaceSlice(eRule.ToFQDNs)...)
			l4 := append(eRule.ToPorts, icmpRules(eRule.ICMPs)...)
			entry := &types.PolicyEntry{
				EndpointSelector: es,
				Labels:           rule.Labels,
				DefaultDeny:      defaultDeny,
				Deny:             false,
				Ingress:          false,
				L3:               l3,
				L4:               l4,
				Authentication:   eRule.Authentication,
				Log:              rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, eRule := range rule.EgressDeny {
			defaultDeny := rule.EnableDefaultDeny.Egress != nil && *rule.EnableDefaultDeny.Egress
			req := convertToLabelSelectorRequirementSlice(eRule.ToRequires)
			l3 := types.ToEndpointSelectorInterfaceSlice(eRule.GetDestinationEndpointSelectorsWithRequirements(req))
			l4 := append(portDenyRulesToPortRules(eRule.ToPorts), icmpRules(eRule.ICMPs)...)
			entry := &types.PolicyEntry{
				EndpointSelector: es,
				Labels:           rule.Labels,
				DefaultDeny:      defaultDeny,
				Deny:             true,
				Ingress:          false,
				L3:               l3,
				L4:               l4,
				Log:              rule.Log,
			}
			entries = append(entries, entry)
		}
	}
	return entries
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

func getSelector(rule *api.Rule) api.EndpointSelector {
	if es := rule.NodeSelector; es.LabelSelector != nil {
		return es
	}
	return rule.EndpointSelector
}
