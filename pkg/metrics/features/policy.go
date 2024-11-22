// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/policy/api"
)

type RuleFeatures struct {
	L3                bool
	Host              bool
	DNS               bool
	HTTP              bool
	HTTPHeaderMatches bool
	OtherL7           bool
	Deny              bool
	IngressCIDRGroup  bool
	MutualAuth        bool
	TLSInspection     bool
	SNIAllowList      bool
}

func (m Metrics) AddRule(r api.Rule) {
	rf := ruleType(r)

	if rf.L3 {
		if m.NPL3L4Ingested.Get() == 0 {
			m.NPL3L4Ingested.Inc()
		}
		m.NPL3L4Present.Inc()
	}
	if rf.Host {
		if m.NPHostNPIngested.Get() == 0 {
			m.NPHostNPIngested.Inc()
		}
		m.NPHostNPPresent.Inc()
	}
	if rf.DNS {
		if m.NPDNSIngested.Get() == 0 {
			m.NPDNSIngested.Inc()
		}
		m.NPDNSPresent.Inc()
	}
	if rf.HTTP {
		if m.NPHTTPIngested.Get() == 0 {
			m.NPHTTPIngested.Inc()
		}
		m.NPHTTPPresent.Inc()
	}
	if rf.HTTPHeaderMatches {
		if m.NPHTTPHeaderMatchesIngested.Get() == 0 {
			m.NPHTTPHeaderMatchesIngested.Inc()
		}
		m.NPHTTPHeaderMatchesPresent.Inc()
	}
	if rf.OtherL7 {
		if m.NPOtherL7Ingested.Get() == 0 {
			m.NPOtherL7Ingested.Inc()
		}
		m.NPOtherL7Present.Inc()
	}
	if rf.Deny {
		if m.NPDenyPoliciesIngested.Get() == 0 {
			m.NPDenyPoliciesIngested.Inc()
		}
		m.NPDenyPoliciesPresent.Inc()
	}
	if rf.IngressCIDRGroup {
		if m.NPIngressCIDRGroupIngested.Get() == 0 {
			m.NPIngressCIDRGroupIngested.Inc()
		}
		m.NPIngressCIDRGroupPresent.Inc()
	}
	if rf.MutualAuth {
		if m.NPMutualAuthIngested.Get() == 0 {
			m.NPMutualAuthIngested.Inc()
		}
		m.NPMutualAuthPresent.Inc()
	}
	if rf.TLSInspection {
		if m.NPTLSInspectionIngested.Get() == 0 {
			m.NPTLSInspectionIngested.Inc()
		}
		m.NPTLSInspectionPresent.Inc()
	}
	if rf.SNIAllowList {
		if m.NPSNIAllowListIngested.Get() == 0 {
			m.NPSNIAllowListIngested.Inc()
		}
		m.NPSNIAllowListPresent.Inc()
	}
}

func (m Metrics) DelRule(r api.Rule) {
	rf := ruleType(r)

	if rf.L3 {
		m.NPL3L4Present.Dec()
	}
	if rf.Host {
		m.NPHostNPPresent.Dec()
	}
	if rf.DNS {
		m.NPDNSPresent.Dec()
	}
	if rf.HTTP {
		m.NPHTTPPresent.Dec()
	}
	if rf.HTTPHeaderMatches {
		m.NPHTTPHeaderMatchesPresent.Dec()
	}
	if rf.OtherL7 {
		m.NPOtherL7Present.Dec()
	}
	if rf.Deny {
		m.NPDenyPoliciesPresent.Dec()
	}
	if rf.IngressCIDRGroup {
		m.NPIngressCIDRGroupPresent.Dec()
	}
	if rf.MutualAuth {
		m.NPMutualAuthPresent.Dec()
	}
	if rf.TLSInspection {
		m.NPTLSInspectionPresent.Dec()
	}
	if rf.SNIAllowList {
		m.NPSNIAllowListPresent.Dec()
	}
}

func (rf *RuleFeatures) allFeaturesIngressCommon() bool {
	return rf.L3 && rf.Host && rf.IngressCIDRGroup
}

func (rf *RuleFeatures) allFeaturesEgressCommon() bool {
	return rf.L3 && rf.Host
}

func (rf *RuleFeatures) allFeaturesPortRules() bool {
	return rf.DNS && rf.HTTP && rf.HTTPHeaderMatches && rf.OtherL7 && rf.TLSInspection && rf.SNIAllowList
}

func ruleTypeIngressCommon(rf *RuleFeatures, i api.IngressCommonRule) {
	if len(i.FromNodes) > 0 {
		rf.Host = true
		rf.L3 = true
	}
	for _, cidrRuleSet := range i.FromCIDRSet {
		if cidrRuleSet.CIDRGroupRef != "" {
			rf.IngressCIDRGroup = true
			rf.L3 = true
		}
	}
	if !rf.L3 && i.IsL3() {
		rf.L3 = true
	}
}

func ruleTypeEgressCommon(rf *RuleFeatures, e api.EgressCommonRule) {
	if len(e.ToNodes) > 0 {
		rf.Host = true
		rf.L3 = true
	}

	if !rf.L3 && e.IsL3() {
		rf.L3 = true
	}
}

func ruleTypePortRules(rf *RuleFeatures, portRules api.PortRules) {
	for _, p := range portRules {
		if p.Rules != nil && len(p.Rules.DNS) > 0 {
			rf.DNS = true
		}
		if p.Rules != nil && len(p.Rules.HTTP) > 0 {
			rf.HTTP = true
			if !rf.HTTPHeaderMatches {
				for _, httpRule := range p.Rules.HTTP {
					if len(httpRule.HeaderMatches) > 0 {
						rf.HTTPHeaderMatches = true
					}
				}
			}
		}
		if p.Rules != nil && (len(p.Rules.L7) > 0 || len(p.Rules.Kafka) > 0) {
			rf.OtherL7 = true
		}
		if !rf.TLSInspection && (p.OriginatingTLS != nil || p.TerminatingTLS != nil) {
			rf.TLSInspection = true
		}
		if !rf.SNIAllowList && len(p.ServerNames) != 0 {
			rf.SNIAllowList = true
		}
		if rf.allFeaturesPortRules() {
			break
		}
	}
}

func ruleType(r api.Rule) RuleFeatures {

	var rf RuleFeatures

	for _, i := range r.Ingress {
		ruleTypeIngressCommon(&rf, i.IngressCommonRule)
		if !rf.allFeaturesPortRules() {
			ruleTypePortRules(&rf, i.ToPorts)
		}
		if i.Authentication != nil {
			rf.MutualAuth = true
		}
		if rf.allFeaturesIngressCommon() && rf.allFeaturesPortRules() && rf.MutualAuth {
			break
		}
	}

	if !(rf.allFeaturesIngressCommon() && rf.Deny) {
		for _, i := range r.IngressDeny {
			ruleTypeIngressCommon(&rf, i.IngressCommonRule)
			rf.Deny = true
			if rf.allFeaturesIngressCommon() && rf.Deny {
				break
			}
		}
	}

	if !(rf.allFeaturesEgressCommon() && rf.allFeaturesPortRules() && rf.MutualAuth) {
		for _, e := range r.Egress {
			ruleTypeEgressCommon(&rf, e.EgressCommonRule)
			if !rf.allFeaturesPortRules() {
				if len(e.ToFQDNs) > 0 {
					rf.DNS = true
				}
				ruleTypePortRules(&rf, e.ToPorts)
			}
			if e.Authentication != nil {
				rf.MutualAuth = true
			}
			if rf.allFeaturesEgressCommon() && rf.allFeaturesPortRules() && rf.MutualAuth {
				break
			}
		}
	}

	if !(rf.allFeaturesEgressCommon() && rf.Deny) {
		for _, e := range r.EgressDeny {
			rf.Deny = true
			ruleTypeEgressCommon(&rf, e.EgressCommonRule)
			if rf.allFeaturesEgressCommon() && rf.Deny {
				break
			}
		}
	}
	return rf
}
