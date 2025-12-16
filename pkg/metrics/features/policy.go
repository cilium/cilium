// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
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

func (m Metrics) AddRule(r types.PolicyEntry) {
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

func (m Metrics) DelRule(r types.PolicyEntry) {
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

func (rf *RuleFeatures) allFeaturesPortRules() bool {
	return rf.DNS && rf.HTTP && rf.HTTPHeaderMatches && rf.OtherL7 && rf.TLSInspection && rf.SNIAllowList
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

func ruleType(r types.PolicyEntry) RuleFeatures {

	var rf RuleFeatures

	rf.Deny = r.IsDeny()
	rf.MutualAuth = r.Authentication != nil
	rf.NonDefaultDeny = r.DefaultDeny
	rf.ToFQDNs, rf.Host, rf.IngressCIDRGroup = r.L3.GetRuleTypes()
	rf.L3 = len(r.L3) > 0 && !rf.ToFQDNs
	ruleTypePortRules(&rf, r.L4)

	return rf
}
