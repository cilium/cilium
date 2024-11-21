// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/policy/api"
)

type RuleFeatures struct {
	L3   bool
	Host bool
	DNS  bool
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
}

func (rf *RuleFeatures) allFeaturesIngressCommon() bool {
	return rf.L3 && rf.Host
}

func (rf *RuleFeatures) allFeaturesEgressCommon() bool {
	return rf.L3 && rf.Host
}

func (rf *RuleFeatures) allFeaturesPortRules() bool {
	return rf.DNS
}

func ruleTypeIngressCommon(rf *RuleFeatures, i api.IngressCommonRule) {
	if len(i.FromNodes) > 0 {
		rf.Host = true
		rf.L3 = true
	}
	for _, cidrRuleSet := range i.FromCIDRSet {
		if cidrRuleSet.CIDRGroupRef != "" {
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
		if rf.allFeaturesIngressCommon() && rf.allFeaturesPortRules() {
			break
		}
	}

	if !(rf.allFeaturesIngressCommon()) {
		for _, i := range r.IngressDeny {
			ruleTypeIngressCommon(&rf, i.IngressCommonRule)
			if rf.allFeaturesIngressCommon() {
				break
			}
		}
	}

	if !(rf.allFeaturesEgressCommon() && rf.allFeaturesPortRules()) {
		for _, e := range r.Egress {
			ruleTypeEgressCommon(&rf, e.EgressCommonRule)
			if !rf.allFeaturesPortRules() {
				if len(e.ToFQDNs) > 0 {
					rf.DNS = true
				}
				ruleTypePortRules(&rf, e.ToPorts)
			}
			if rf.allFeaturesEgressCommon() && rf.allFeaturesPortRules() {
				break
			}
		}
	}

	if !(rf.allFeaturesEgressCommon()) {
		for _, e := range r.EgressDeny {
			ruleTypeEgressCommon(&rf, e.EgressCommonRule)
			if rf.allFeaturesEgressCommon() {
				break
			}
		}
	}
	return rf
}
