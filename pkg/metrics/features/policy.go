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
	NonDefaultDeny    bool
	ToFQDNs           bool
}

func (m Metrics) AddRule(r api.Rule) {
	rf := ruleType(r)

	if rf.L3 {
		m.NPL3Ingested.WithLabelValues(actionAdd).Inc()
	}
	if rf.Host {
		m.NPHostNPIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.DNS {
		m.NPDNSIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.ToFQDNs {
		m.NPToFQDNsIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.HTTP {
		m.NPHTTPIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.HTTPHeaderMatches {
		m.NPHTTPHeaderMatchesIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.OtherL7 {
		m.NPOtherL7Ingested.WithLabelValues(actionAdd).Inc()
	}
	if rf.Deny {
		m.NPDenyPoliciesIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.IngressCIDRGroup {
		m.NPIngressCIDRGroupIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.MutualAuth {
		m.NPMutualAuthIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.TLSInspection {
		m.NPTLSInspectionIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.SNIAllowList {
		m.NPSNIAllowListIngested.WithLabelValues(actionAdd).Inc()
	}
	if rf.NonDefaultDeny {
		m.NPNonDefaultDenyIngested.WithLabelValues(actionAdd).Inc()
	}
}

func (m Metrics) DelRule(r api.Rule) {
	rf := ruleType(r)

	if rf.L3 {
		m.NPL3Ingested.WithLabelValues(actionDel).Inc()
	}
	if rf.Host {
		m.NPHostNPIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.DNS {
		m.NPDNSIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.ToFQDNs {
		m.NPToFQDNsIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.HTTP {
		m.NPHTTPIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.HTTPHeaderMatches {
		m.NPHTTPHeaderMatchesIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.OtherL7 {
		m.NPOtherL7Ingested.WithLabelValues(actionDel).Inc()
	}
	if rf.Deny {
		m.NPDenyPoliciesIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.IngressCIDRGroup {
		m.NPIngressCIDRGroupIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.MutualAuth {
		m.NPMutualAuthIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.TLSInspection {
		m.NPTLSInspectionIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.SNIAllowList {
		m.NPSNIAllowListIngested.WithLabelValues(actionDel).Inc()
	}
	if rf.NonDefaultDeny {
		m.NPNonDefaultDenyIngested.WithLabelValues(actionDel).Inc()
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

	rf.NonDefaultDeny =
		r.EnableDefaultDeny.Ingress != nil && *r.EnableDefaultDeny.Ingress ||
			r.EnableDefaultDeny.Egress != nil && *r.EnableDefaultDeny.Egress

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
			if !(rf.allFeaturesPortRules() && rf.ToFQDNs) {
				if len(e.ToFQDNs) > 0 {
					rf.ToFQDNs = true
				}
				ruleTypePortRules(&rf, e.ToPorts)
			}
			if e.Authentication != nil {
				rf.MutualAuth = true
			}
			if rf.allFeaturesEgressCommon() && rf.allFeaturesPortRules() && rf.MutualAuth && rf.ToFQDNs {
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
