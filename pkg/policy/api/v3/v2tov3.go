// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	"github.com/cilium/cilium/pkg/policy/api/v2"
)

// V2RulesTov3RulesSanitized translates the given v2Rules to the respective v3
// Rules.
// All given v2Rules needs to be sanitized and the returned v3 Rules will be
// already sanitized. In case of an error while sanitizing a rule, that error
// will be returned.
func V2RulesTov3RulesSanitized(v2Rules *v2.Rules) (*Rules, error) {
	v3Rules := V2RulesTov3Rules(v2Rules)
	for _, v3Rule := range *v3Rules {
		err := v3Rule.Sanitize()
		if err != nil {
			return nil, err
		}
	}
	return v3Rules, nil
}

// V2RuleTov3RuleSanitized translates the given v2Rule to the respective v3
// Rule.
// The given v2Rules needs to be sanitized and the returned v3 Rule is alread
// sanitized. In case of an error while sanitizing a rule, that error
// will be returned.
func V2RuleTov3RuleSanitized(v2Rule *v2.Rule) (*Rule, error) {
	v3Rule := V2RuleTov3Rule(v2Rule)
	if v3Rule == nil {
		return nil, nil
	}
	err := v3Rule.Sanitize()
	if err != nil {
		return nil, err
	}
	return v3Rule, nil
}

// V2RulesTov3Rules translates the given v2Rules to the respective v3 Rules.
// All given v2Rules needs to be sanitized and the returned v3 Rules needs to
// be sanitized.
func V2RulesTov3Rules(v2Rules *v2.Rules) *Rules {
	if v2Rules == nil {
		return nil
	}
	v3Rules := make(Rules, len(*v2Rules))
	for i, v := range *v2Rules {
		v3Rules[i] = V2RuleTov3Rule(v)
	}
	return &v3Rules
}

// V2RuleTov3Rule translates the given v2Rule to the respective v3 Rule.
// The given v2Rule needs to be sanitized and the returned v3Rule needs to
// be sanitized.
func V2RuleTov3Rule(v2Rule *v2.Rule) *Rule {
	if v2Rule == nil {
		return nil
	}
	v3Rule := &Rule{}

	v3Rule.EndpointSelector = *v2ESTov3ES(&v2Rule.EndpointSelector)

	if v2Rule.Ingress != nil {
		v3Rule.Ingress = []IngressRule{}

		for _, v := range v2Rule.Ingress {
			v3Rule.Ingress = append(v3Rule.Ingress, v2IRTov3IR(&v)...)
		}
	}

	if v2Rule.Egress != nil {
		v3Rule.Egress = []EgressRule{}

		for _, v := range v2Rule.Egress {
			v3Rule.Egress = append(v3Rule.Egress, v2ERTov3ER(&v)...)
		}
	}

	v3Rule.Labels = v2Rule.Labels.DeepCopy()
	v3Rule.Description = v2Rule.Description

	return v3Rule
}

func v2ESTov3ES(v2ES *v2.EndpointSelector) *IdentitySelector {
	if v2ES == nil {
		return nil
	}

	v3ES := &IdentitySelector{}

	if v2ES.LabelSelector != nil {
		v3ES.LabelSelector = v2ES.LabelSelector.DeepCopy()
	}

	return v3ES
}

func v2IRTov3IR(v2IR *v2.IngressRule) []IngressRule {
	if v2IR == nil {
		return nil
	}
	var (
		v3IR []IngressRule
		v3PR []*PortRule
	)

	if v2IR.ToPorts != nil {
		v3PR = make([]*PortRule, len(v2IR.ToPorts))

		for i, v := range v2IR.ToPorts {
			v3PR[i] = v2PRTov3PR(&v)
		}
	}

	if v2IR.FromCIDR != nil {
		fromCIDRs := &CIDRRule{
			CIDR: make([]CIDR, len(v2IR.FromCIDR)),
		}
		for i, v := range v2IR.FromCIDR {
			fromCIDRs.CIDR[i] = v2CIDRTov3CIDR(v)
		}
		if v3IR == nil {
			v3IR = []IngressRule{}
		}

		if v3PR != nil {
			for _, v := range v3PR {
				cpy := fromCIDRs.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3IR = append(v3IR, IngressRule{FromCIDRs: cpy})
			}
		} else {
			v3IR = append(v3IR, IngressRule{FromCIDRs: fromCIDRs})
		}
	}

	for _, v := range v2IR.FromCIDRSet {
		fromCIDRs := v2CIDRRuleTov3CIDRRule(&v)

		if v3IR == nil {
			v3IR = []IngressRule{}
		}

		if v3PR != nil {
			for _, v := range v3PR {
				cpy := fromCIDRs.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3IR = append(v3IR, IngressRule{FromCIDRs: cpy})
			}
		} else {
			v3IR = append(v3IR, IngressRule{FromCIDRs: fromCIDRs})
		}
	}

	for _, v := range v2IR.FromEndpoints {
		fromIdentities := &IdentityRule{
			IdentitySelector: *v2ESTov3ES(&v),
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		if v3PR != nil {
			for _, v := range v3PR {
				cpy := fromIdentities.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3IR = append(v3IR, IngressRule{FromIdentities: cpy})
			}
		} else {
			v3IR = append(v3IR, IngressRule{FromIdentities: fromIdentities})
		}
	}

	for _, v := range v2IR.FromRequires {
		fromRequires := &EndpointRequire{
			IdentitySelector: []IdentitySelector{*v2ESTov3ES(&v)},
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		v3IR = append(v3IR, IngressRule{FromRequires: fromRequires})
	}

	for _, v := range v2IR.FromEntities {
		fromEntities := &EntityRule{
			Entities: []Entity{*v2EntityTov3Entity(&v)},
		}

		if v3IR == nil {
			v3IR = []IngressRule{}
		}
		if v3PR != nil {
			for _, v := range v3PR {
				cpy := fromEntities.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3IR = append(v3IR, IngressRule{FromEntities: cpy})
			}
		} else {
			v3IR = append(v3IR, IngressRule{FromEntities: fromEntities})
		}
	}

	// If the v2 Ingress Rule contains a L4-only rule then
	// the translation will be applied to all types of ingress traffic.
	if v3PR != nil &&
		v2IR.FromRequires == nil &&
		v2IR.FromEntities == nil &&
		v2IR.FromEndpoints == nil &&
		v2IR.FromCIDR == nil &&
		v2IR.FromCIDRSet == nil {

		for _, v := range v3PR {
			v3IR = append(v3IR,
				IngressRule{FromCIDRs: &CIDRRule{CIDR: NewWildcardCIDR(), ToPorts: v.DeepCopy()}},
				IngressRule{FromEntities: &EntityRule{Entities: []Entity{Entity(EntityAll)}, ToPorts: v.DeepCopy()}},
				IngressRule{FromIdentities: &IdentityRule{IdentitySelector: NewWildcardIdentitySelector(), ToPorts: v.DeepCopy()}},
			)
		}
	}

	return v3IR
}

func v2ERTov3ER(v2ER *v2.EgressRule) []EgressRule {
	if v2ER == nil {
		return nil
	}

	var (
		v3ER []EgressRule
		v3PR []*PortRule
	)

	if v2ER.ToPorts != nil {
		v3PR = make([]*PortRule, len(v2ER.ToPorts))
	}
	for i, v := range v2ER.ToPorts {
		v3PR[i] = v2PRTov3PR(&v)
	}

	if v2ER.ToCIDR != nil {
		toCIDRs := &CIDRRule{
			CIDR: make([]CIDR, len(v2ER.ToCIDR)),
		}
		for i, v := range v2ER.ToCIDR {
			toCIDRs.CIDR[i] = v2CIDRTov3CIDR(v)
		}
		if v3ER == nil {
			v3ER = []EgressRule{}
		}

		if v3PR != nil {
			for _, v := range v3PR {
				cpy := toCIDRs.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3ER = append(v3ER, EgressRule{ToCIDRs: cpy})
			}
		} else {
			v3ER = append(v3ER, EgressRule{ToCIDRs: toCIDRs})
		}
	}

	for _, v := range v2ER.ToCIDRSet {
		toCIDRs := v2CIDRRuleTov3CIDRRule(&v)

		if v3ER == nil {
			v3ER = []EgressRule{}
		}

		if v3PR != nil {
			for _, v := range v3PR {
				cpy := toCIDRs.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3ER = append(v3ER, EgressRule{ToCIDRs: cpy})
			}
		} else {
			v3ER = append(v3ER, EgressRule{ToCIDRs: toCIDRs})
		}
	}

	for _, v := range v2ER.ToEndpoints {
		toIdentities := &IdentityRule{
			IdentitySelector: *v2ESTov3ES(&v),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		if v3PR != nil {
			for _, v := range v3PR {
				cpy := toIdentities.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3ER = append(v3ER, EgressRule{ToIdentities: cpy})
			}
		} else {
			v3ER = append(v3ER, EgressRule{ToIdentities: toIdentities})
		}
	}

	for _, v := range v2ER.ToRequires {
		toRequires := &EndpointRequire{
			IdentitySelector: []IdentitySelector{*v2ESTov3ES(&v)},
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		v3ER = append(v3ER, EgressRule{ToRequires: toRequires})
	}

	for _, v := range v2ER.ToEntities {
		toEntities := &EntityRule{
			Entities: []Entity{*v2EntityTov3Entity(&v)},
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		if v3PR != nil {
			for _, v := range v3PR {
				cpy := toEntities.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3ER = append(v3ER, EgressRule{ToEntities: cpy})
			}
		} else {
			v3ER = append(v3ER, EgressRule{ToEntities: toEntities})
		}
	}

	for _, v := range v2ER.ToServices {
		toServices := &ServiceRule{
			K8sServiceSelector: v2K8sSSNTov3K8sSSN(v.K8sServiceSelector),
			K8sService:         v2K8sSNTov3K8sSN(v.K8sService),
		}

		if v3ER == nil {
			v3ER = []EgressRule{}
		}
		if v3PR != nil {
			for _, v := range v3PR {
				cpy := toServices.DeepCopy()
				cpy.ToPorts = v.DeepCopy()
				v3ER = append(v3ER, EgressRule{ToServices: cpy})
			}
		} else {
			v3ER = append(v3ER, EgressRule{ToServices: toServices})
		}
	}

	// If the v2 Egress Rule contains a L4-only rule then
	// the translation will be applied to all types of egress traffic.
	if v3PR != nil &&
		v2ER.ToRequires == nil &&
		v2ER.ToEntities == nil &&
		v2ER.ToEndpoints == nil &&
		v2ER.ToCIDR == nil &&
		v2ER.ToCIDRSet == nil &&
		v2ER.ToServices == nil {

		for _, v := range v3PR {
			v3ER = append(v3ER,
				EgressRule{ToCIDRs: &CIDRRule{CIDR: NewWildcardCIDR(), ToPorts: v.DeepCopy()}},
				EgressRule{ToEntities: &EntityRule{Entities: []Entity{Entity(EntityAll)}, ToPorts: v.DeepCopy()}},
				EgressRule{ToIdentities: &IdentityRule{IdentitySelector: NewWildcardIdentitySelector(), ToPorts: v.DeepCopy()}},
			)
		}
	}

	return v3ER
}

func v2CIDRRuleTov3CIDRRule(v2CR *v2.CIDRRule) *CIDRRule {
	if v2CR == nil {
		return nil
	}

	v3CR := &CIDRRule{}

	v2CRCpy := v2CR.DeepCopy()

	v3CR.CIDR = []CIDR{
		v2CIDRTov3CIDR(v2CRCpy.Cidr),
	}

	if v2CR.ExceptCIDRs != nil {
		v3CR.ExceptCIDRs = make([]CIDR, len(v2CR.ExceptCIDRs))

		for i, v := range v2CR.ExceptCIDRs {
			v3CR.ExceptCIDRs[i] = v2CIDRTov3CIDR(v)
		}
	}

	v3CR.Generated = v2CR.Generated

	return v3CR
}

func v2CIDRTov3CIDR(v2C v2.CIDR) CIDR {
	return CIDR(string(v2C))
}

func v2EntityTov3Entity(v2E *v2.Entity) *Entity {
	if v2E == nil {
		return nil
	}
	e := Entity(string(*v2E))
	return &e
}

func v2PRTov3PR(v2PR *v2.PortRule) *PortRule {
	if v2PR == nil {
		return nil
	}

	v3PR := &PortRule{}

	if v2PR.Rules != nil {
		v3PR.Rules = &L7Rules{}
		if v2PR.Rules.HTTP != nil {
			v3PR.Rules.HTTP = []PortRuleHTTP{}
		}
		for _, v := range v2PR.Rules.HTTP {
			http := *v2PRHTTPTov3PRHTTP(&v)
			v3PR.Rules.HTTP = append(v3PR.Rules.HTTP, http)
		}

		if v2PR.Rules.Kafka != nil {
			v3PR.Rules.Kafka = []PortRuleKafka{}
		}
		for _, v := range v2PR.Rules.Kafka {
			kafka := *v2PRKafkaTov3PRKafka(&v)
			v3PR.Rules.Kafka = append(v3PR.Rules.Kafka, kafka)
		}
	}

	if v2PR.Ports != nil {
		v3PR.Ports = make([]PortProtocol, len(v2PR.Ports))
		for i, v := range v2PR.Ports {
			v3PR.Ports[i] = *v2PPTov3PP(&v)
		}
	}

	return v3PR
}

func v2PRHTTPTov3PRHTTP(v2PRH *v2.PortRuleHTTP) *PortRuleHTTP {
	if v2PRH == nil {
		return nil
	}

	v3PRH := PortRuleHTTP{
		Host:   v2PRH.Host,
		Method: v2PRH.Method,
		Path:   v2PRH.Path,
	}

	if v2PRH.Headers != nil {
		v3PRH.Headers = make([]string, len(v2PRH.Headers))
		copy(v3PRH.Headers, v2PRH.Headers)
	}

	return &v3PRH
}

func v2PRKafkaTov3PRKafka(v2K *v2.PortRuleKafka) *PortRuleKafka {
	if v2K == nil {
		return nil
	}

	return &PortRuleKafka{
		Role:       v2K.Role,
		APIKey:     v2K.APIKey,
		APIVersion: v2K.APIVersion,
		ClientID:   v2K.ClientID,
		Topic:      v2K.Topic,
	}
}

func v2PPTov3PP(v2PP *v2.PortProtocol) *PortProtocol {
	if v2PP == nil {
		return nil
	}

	return &PortProtocol{
		Port:     v2PP.Port,
		Protocol: L4Proto(string(v2PP.Protocol)),
	}
}

func v2K8sSNTov3K8sSN(v2K8sSN *v2.K8sServiceNamespace) *K8sServiceNamespace {
	if v2K8sSN == nil {
		return nil
	}

	return &K8sServiceNamespace{
		Namespace:   v2K8sSN.Namespace,
		ServiceName: v2K8sSN.ServiceName,
	}
}

func v2K8sSSNTov3K8sSSN(k8sSSN *v2.K8sServiceSelectorNamespace) *K8sServiceSelectorNamespace {

	if k8sSSN == nil {
		return nil
	}

	return &K8sServiceSelectorNamespace{
		Selector:  v2SSTov3SS(k8sSSN.Selector),
		Namespace: k8sSSN.Namespace,
	}

}

func v2SSTov3SS(v2SS v2.ServiceSelector) ServiceSelector {
	es := v2.EndpointSelector(v2SS)
	sel := v2ESTov3ES(&es)
	if sel == nil {
		return ServiceSelector(IdentitySelector{})
	}
	return ServiceSelector(*sel)
}
