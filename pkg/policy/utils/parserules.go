// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	fqdnconfig "github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

type ruleParserConfig struct {
	fqdn            fqdnconfig.FQDNPolicyDNSServerConfig
	serviceResolver fqdnconfig.ServiceResolver
}

type RuleParserOption func(*ruleParserConfig)

func WithFQDNPolicyDNSServerConfig(cfg fqdnconfig.FQDNPolicyDNSServerConfig) RuleParserOption {
	return func(c *ruleParserConfig) {
		c.fqdn = cfg
	}
}

func WithServiceResolver(resolver fqdnconfig.ServiceResolver) RuleParserOption {
	return func(c *ruleParserConfig) {
		c.serviceResolver = resolver
	}
}

// RulesToPolicyEntries converts the external rule type to the internal policy entry representation.
func RulesToPolicyEntries(rules api.Rules, opts ...RuleParserOption) types.PolicyEntries {
	cfg := &ruleParserConfig{
		fqdn: fqdnconfig.DefaultFQDNPolicyDNSServerConfig,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	entries := types.PolicyEntries{}
	for _, rule := range rules {
		ls, node := getSelector(rule)

		subjectSelector := types.NewLabelSelector(ls)

		for _, iRule := range rule.Ingress {
			defaultDeny := rule.EnableDefaultDeny.Ingress == nil || *rule.EnableDefaultDeny.Ingress

			l3 := mergeEndpointSelectors(
				iRule.FromEndpoints,
				iRule.FromNodes,
				iRule.FromEntities,
				iRule.FromCIDR,
				iRule.FromCIDRSet,
				nil,
				iRule.FromGroups)

			l4 := make(api.PortRules, 0, len(iRule.ToPorts)+len(iRule.ICMPs))
			l4 = append(l4, iRule.ToPorts...)
			l4 = append(l4, icmpRules(iRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Tier:           types.Normal,
				Subject:        subjectSelector,
				Node:           node,
				Labels:         rule.Labels,
				DefaultDeny:    defaultDeny,
				Verdict:        types.Allow,
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

			l3 := mergeEndpointSelectors(
				iRule.FromEndpoints,
				iRule.FromNodes,
				iRule.FromEntities,
				iRule.FromCIDR,
				iRule.FromCIDRSet,
				nil,
				iRule.FromGroups)

			l4 := make(api.PortRules, 0, len(iRule.ToPorts)+len(iRule.ICMPs))
			l4 = append(l4, portDenyRulesToPortRules(iRule.ToPorts)...)
			l4 = append(l4, icmpRules(iRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Tier:        types.Normal,
				Subject:     subjectSelector,
				Node:        node,
				Labels:      rule.Labels,
				DefaultDeny: defaultDeny,
				Verdict:     types.Deny,
				Ingress:     true,
				L3:          l3,
				L4:          l4,
				Log:         rule.Log,
			}
			entries = append(entries, entry)
		}

		for _, eRule := range rule.Egress {
			defaultDeny := rule.EnableDefaultDeny.Egress == nil || *rule.EnableDefaultDeny.Egress

			l3 := mergeEndpointSelectors(
				eRule.ToEndpoints,
				eRule.ToNodes,
				eRule.ToEntities,
				eRule.ToCIDR,
				eRule.ToCIDRSet,
				eRule.ToFQDNs,
				eRule.ToGroups)

			l4 := make(api.PortRules, 0, len(eRule.ToPorts)+len(eRule.ICMPs))
			l4 = append(l4, eRule.ToPorts...)
			l4 = append(l4, icmpRules(eRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Tier:           types.Normal,
				Subject:        subjectSelector,
				Node:           node,
				Labels:         rule.Labels,
				DefaultDeny:    defaultDeny,
				Verdict:        types.Allow,
				Ingress:        false,
				L3:             l3,
				L4:             l4,
				Authentication: eRule.Authentication,
				Log:            rule.Log,
			}
			entries = append(entries, entry)

			if len(eRule.ToFQDNs) > 0 {
				l3, l4 := cfg.fqdn.DNSSelectors(cfg.serviceResolver, toPortRulesDNS(eRule.ToFQDNs))
				if len(l3) > 0 {
					entries = append(entries, &types.PolicyEntry{
						Tier:        types.Normal,
						Subject:     subjectSelector,
						Node:        node,
						Labels:      rule.Labels,
						DefaultDeny: defaultDeny,
						Verdict:     types.Allow,
						Ingress:     false,
						L3:          l3,
						L4:          l4,
						Log:         rule.Log,
					})
				}
			}
		}

		for _, eRule := range rule.EgressDeny {
			defaultDeny := rule.EnableDefaultDeny.Egress == nil || *rule.EnableDefaultDeny.Egress

			l3 := mergeEndpointSelectors(
				eRule.ToEndpoints,
				eRule.ToNodes,
				eRule.ToEntities,
				eRule.ToCIDR,
				eRule.ToCIDRSet,
				nil,
				eRule.ToGroups)

			l4 := make(api.PortRules, 0, len(eRule.ToPorts)+len(eRule.ICMPs))
			l4 = append(l4, portDenyRulesToPortRules(eRule.ToPorts)...)
			l4 = append(l4, icmpRules(eRule.ICMPs)...)

			entry := &types.PolicyEntry{
				Tier:        types.Normal,
				Subject:     subjectSelector,
				Node:        node,
				Labels:      rule.Labels,
				DefaultDeny: defaultDeny,
				Verdict:     types.Deny,
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

func mergeEndpointSelectors(endpoints, nodes api.EndpointSelectorSlice, entities api.EntitySlice, cidrSlice api.CIDRSlice, cidrRuleSlice api.CIDRRuleSlice, fqdns api.FQDNSelectorSlice, groups []api.Groups) types.Selectors {
	// Explicitly check for empty non-nil slices, it should not result in any identity being selected.
	// Note that this works due to only one selector type being allowed in a single API rule.
	if (endpoints != nil && len(endpoints) == 0) ||
		(nodes != nil && len(nodes) == 0) ||
		(entities != nil && len(entities) == 0) ||
		(cidrSlice != nil && len(cidrSlice) == 0) ||
		(cidrRuleSlice != nil && len(cidrRuleSlice) == 0) {
		return nil
	}
	l3 := make(types.Selectors, 0, len(endpoints)+len(nodes)+len(entities)+len(cidrSlice)+len(cidrRuleSlice)+len(fqdns))
	l3 = append(l3, types.ToSelectors(endpoints...)...)
	l3 = append(l3, types.ToSelectors(nodes...)...)
	l3 = append(l3, types.ToSelectors(entities.GetAsEndpointSelectors()...)...)
	l3 = append(l3, types.ToSelectors(cidrSlice...)...)
	l3 = append(l3, types.ToSelectors(cidrRuleSlice...)...)
	l3 = append(l3, types.ToSelectors(fqdns...)...)
	l3 = append(l3, types.ToSelectors(groups...)...)
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

// getSelector returns either the endpoint selector, which is the target of a policy rule and true if the endpoint represents a node.
func getSelector(rule *api.Rule) (api.EndpointSelector, bool) {
	if es := rule.NodeSelector; es.LabelSelector != nil {
		return es, true
	}
	return rule.EndpointSelector, false
}

// toPortRulesDNS converts a slice of FQDN selectors into an L7 PortRulesDNS slice for rule parsing.
func toPortRulesDNS(toFQDNs api.FQDNSelectorSlice) api.PortRulesDNS {
	dnsRules := make(api.PortRulesDNS, 0, len(toFQDNs))
	for _, fqdn := range toFQDNs {
		dnsRules = append(dnsRules, api.PortRuleDNS(fqdn))
	}
	return dnsRules
}
