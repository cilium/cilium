// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/sirupsen/logrus"
)

type rule struct {
	api.Rule

	fromEntities []api.EndpointSelector
	toEntities   []api.EndpointSelector
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

// sanitize has a side effect of populating the fromEntities and toEntities
// slices to avoid superfluent map accesses
func (r *rule) sanitize() error {
	if r == nil || r.EndpointSelector.LabelSelector == nil {
		return fmt.Errorf("nil rule")
	}

	if err := r.Rule.Sanitize(); err != nil {
		return err
	}

	// resetting entity selector slices
	r.fromEntities = []api.EndpointSelector{}
	r.toEntities = []api.EndpointSelector{}
	entities := []api.Entity{}

	ingressEntityCounter := 0
	for _, rule := range r.Ingress {
		entities = append(entities, rule.FromEntities...)
		ingressEntityCounter += len(rule.FromEntities)
	}

	for _, rule := range r.Egress {
		entities = append(entities, rule.ToEntities...)
	}

	for j, entity := range entities {
		selector, ok := api.EntitySelectorMapping[entity]
		if !ok {
			return fmt.Errorf("unsupported entity: %s", entity)
		}

		if j < ingressEntityCounter {
			r.fromEntities = append(r.fromEntities, selector)
		} else {
			r.toEntities = append(r.toEntities, selector)
		}
	}

	return nil
}

func (policy *L4Filter) addEndpoints(endpoints []api.EndpointSelector) bool {

	if len(policy.Endpoints) == 0 && len(endpoints) > 0 {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: endpoints,
			"policy":                   policy,
		}).Debug("skipping L4 filter as the endpoints are already covered.")
		return true
	}

	if len(policy.Endpoints) > 0 && len(endpoints) == 0 {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: endpoints,
			"policy":                   policy,
		}).Debug("new L4 filter applies to all endpoints, making the policy more permissive.")
		policy.Endpoints = nil
	}

	policy.Endpoints = append(policy.Endpoints, endpoints...)
	return false
}

func mergeL4IngressPort(ctx *SearchContext, endpoints []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(proto)
	filter, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4IngressFilter(endpoints, r, p, proto, ruleLabels)
		return 1, nil
	}
	l4Filter := CreateL4IngressFilter(endpoints, r, p, proto, ruleLabels)
	if l4Filter.L7Parser != "" {
		if filter.L7Parser == "" {
			filter.L7Parser = l4Filter.L7Parser
		} else if l4Filter.L7Parser != filter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", l4Filter.L7Parser, filter.L7Parser)
			return 0, fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", l4Filter.L7Parser, filter.L7Parser)
		}
	}

	if filter.addEndpoints(endpoints) && r.NumRules() == 0 {
		// skip this policy as it is already covered and it does not contain L7 rules
		return 1, nil
	}

	for hash, newL7Rules := range l4Filter.L7RulesPerEp {
		if ep, ok := filter.L7RulesPerEp[hash]; ok {
			switch {
			case len(newL7Rules.HTTP) > 0:
				if len(ep.Kafka) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return 0, fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.HTTP {
					if !newRule.Exists(ep) {
						ep.HTTP = append(ep.HTTP, newRule)
					}
				}
			case len(newL7Rules.Kafka) > 0:
				if len(ep.HTTP) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return 0, fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.Kafka {
					if !newRule.Exists(ep) {
						ep.Kafka = append(ep.Kafka, newRule)
					}
				}
			default:
				ctx.PolicyTrace("   No L7 rules to merge.\n")
			}
			filter.L7RulesPerEp[hash] = ep
		} else {
			filter.L7RulesPerEp[hash] = newL7Rules
		}
	}

	filter.DerivedFromRules = append(filter.DerivedFromRules, ruleLabels)
	resMap[key] = filter
	return 1, nil
}

func mergeL4Ingress(ctx *SearchContext, fromEndpoints []api.EndpointSelector, portRules []api.PortRule,
	ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	if len(portRules) == 0 {
		ctx.PolicyTrace("    No L4 %s rules\n", policymap.Ingress)
		return 0, nil
	}

	found := 0
	var err error

	for _, r := range portRules {
		if fromEndpoints != nil {
			ctx.PolicyTrace("    Allows %s port %v from endpoints %v\n", policymap.Ingress, r.Ports, fromEndpoints)
		} else {
			ctx.PolicyTrace("    Allows %s port %v\n", policymap.Ingress, r.Ports)
		}

		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
		}

		l3match := false
		if ctx.From != nil && fromEndpoints != nil {
			for _, labels := range fromEndpoints {
				if labels.Matches(ctx.From) {
					l3match = true
					break
				}
			}
			if l3match == false {
				ctx.PolicyTrace("      Labels %s not found", ctx.From)
				continue
			}
		}
		ctx.PolicyTrace("      Found all required labels")

		for _, p := range r.Ports {
			var cnt int
			if p.Protocol != api.ProtoAny {
				cnt, err = mergeL4IngressPort(ctx, fromEndpoints, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err = mergeL4IngressPort(ctx, fromEndpoints, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeL4IngressPort(ctx, fromEndpoints, r, p, api.ProtoUDP, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			}
		}
	}

	return found, nil
}

func (state *traceState) selectRule(ctx *SearchContext, r *rule) {
	ctx.PolicyTrace("* Rule %s: selected\n", r)
	state.selectedRules++
}

func (state *traceState) unSelectRule(ctx *SearchContext, labels labels.LabelArray, r *rule) {
	ctx.PolicyTraceVerbose("  Rule %s: did not select %+v\n", r, labels)
}

// resolveL4IngressPolicy determines whether (TODO ianvernon)
func (r *rule) resolveL4IngressPolicy(ctx *SearchContext, state *traceState, result *L4Policy) (*L4Policy, error) {
	//fmt.Printf("resolveL4IngressPolicy: context %s, state %s, result %s\n", ctx, state, result)
	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, ctx.To, r)
		return nil, nil
	}

	state.selectRule(ctx, r)
	found := 0

	if len(r.Ingress) == 0 {
		ctx.PolicyTrace("    No L4 ingress rules\n")
	}
	for _, ingressRule := range r.Ingress {
		cnt, err := mergeL4Ingress(ctx, ingressRule.FromEndpoints, ingressRule.ToPorts, r.Rule.Labels.DeepCopy(), result.Ingress)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			found += cnt
		}
	}

	if found > 0 {
		return result, nil
	}

	return nil, nil
}

// ********************** CIDR POLICY **********************

// mergeCIDR inserts all of the CIDRs in ipRules to resMap. Returns the number
// of CIDRs added to resMap.
func mergeCIDR(ctx *SearchContext, dir string, ipRules []api.CIDR, ruleLabels labels.LabelArray, resMap *CIDRPolicyMap) int {
	found := 0

	for _, r := range ipRules {
		strCIDR := string(r)
		ctx.PolicyTrace("  Allows %s IP %s\n", dir, strCIDR)

		found += resMap.Insert(strCIDR, ruleLabels)
	}

	return found
}

func computeResultantCIDRSet(cidrs []api.CIDRRule) []api.CIDR {
	var allResultantAllowedCIDRs []api.CIDR
	for _, s := range cidrs {
		// No need for error checking, as api.CIDRRule.Sanitize() already does.
		_, allowNet, _ := net.ParseCIDR(string(s.Cidr))

		var removeSubnets []*net.IPNet
		for _, t := range s.ExceptCIDRs {
			// No need for error checking, as api.CIDRRule.Sanitize() already
			// does.
			_, removeSubnet, _ := net.ParseCIDR(string(t))
			removeSubnets = append(removeSubnets, removeSubnet)
		}
		// No need for error checking, as have already validated that none of
		// the possible error cases can occur in ip.RemoveCIDRs
		resultantAllowedCIDRs, _ := ip.RemoveCIDRs([]*net.IPNet{allowNet}, removeSubnets)

		for _, u := range resultantAllowedCIDRs {
			allResultantAllowedCIDRs = append(allResultantAllowedCIDRs, api.CIDR(u.String()))
		}
	}
	return allResultantAllowedCIDRs
}

// resolveCIDRPolicy inserts the CIDRs from the specified rule into result if
// the rule corresponds to the current SearchContext. It returns the resultant
// CIDRPolicy containing the added ingress and egress CIDRs. If no CIDRs are
// added to result, a nil CIDRPolicy is returned.
func (r *rule) resolveCIDRPolicy(ctx *SearchContext, state *traceState, result *CIDRPolicy) *CIDRPolicy {
	// Don't select rule if it doesn't apply to the given context.
	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, ctx.To, r)
		return nil
	}

	state.selectRule(ctx, r)
	found := 0

	for _, ingressRule := range r.Ingress {
		// TODO (ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, ingressRule.FromCIDR...)
		allCIDRs = append(allCIDRs, computeResultantCIDRSet(ingressRule.FromCIDRSet)...)

		for _, fromEntity := range ingressRule.FromEntities {
			switch fromEntity {
			case api.EntityWorld:
				allCIDRs = append(allCIDRs, api.CIDRMatchAll...)
			}
		}

		if cnt := mergeCIDR(ctx, "Ingress", allCIDRs, r.Labels, &result.Ingress); cnt > 0 {
			found += cnt
		}
	}

	for _, egressRule := range r.Egress {
		// TODO(ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, egressRule.ToCIDR...)
		allCIDRs = append(allCIDRs, computeResultantCIDRSet(egressRule.ToCIDRSet)...)

		for _, toEntity := range egressRule.ToEntities {
			switch toEntity {
			case api.EntityWorld:
				allCIDRs = append(allCIDRs, api.CIDRMatchAll...)
			}
		}

		if cnt := mergeCIDR(ctx, "Egress", allCIDRs, r.Labels, &result.Egress); cnt > 0 {
			found += cnt
		}
	}

	if found > 0 {
		return result
	}

	ctx.PolicyTrace("    No L3 rules\n")
	return nil
}

// canReachIngress returns the decision as to whether the set of labels specified
// in ctx.From match with the label selectors specified in the ingress rules
// contained within r.
func (r *rule) canReachIngress(ctx *SearchContext, state *traceState) api.Decision {

	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, ctx.To, r)
		return api.Undecided
	}

	state.selectRule(ctx, r)
	for _, r := range r.Ingress {
		for _, sel := range r.FromRequires {
			ctx.PolicyTrace("    Requires from labels %+v", sel)
			if !sel.Matches(ctx.From) {
				ctx.PolicyTrace("-     Labels %v not found\n", ctx.From)
				state.constrainedRules++
				return api.Denied
			}
			ctx.PolicyTrace("+     Found all required labels\n")
		}
	}

	// separate loop is needed as failure to meet FromRequires always takes
	// precedence over FromEndpoints
	for _, r := range r.Ingress {
		for _, sel := range r.FromEndpoints {
			ctx.PolicyTrace("    Allows from labels %+v", sel)
			if sel.Matches(ctx.From) {
				ctx.PolicyTrace("      Found all required labels")
				if len(r.ToPorts) == 0 {
					ctx.PolicyTrace("+       No L4 restrictions\n")
					state.matchedRules++
					return api.Allowed
				}
				ctx.PolicyTrace("        Rule restricts traffic to specific L4 destinations; deferring policy decision to L4 policy stage\n")
			} else {
				ctx.PolicyTrace("      Labels %v not found\n", ctx.From)
			}
		}
	}

	for _, entitySelector := range r.fromEntities {
		if entitySelector.Matches(ctx.From) {
			ctx.PolicyTrace("+     Found all required labels to match entity %s\n", entitySelector.String())
			state.matchedRules++
			return api.Allowed
		}

	}

	return api.Undecided
}

// ****************** EGRESS POLICY ******************

// canReachEgress returns the decision as to whether the set of labels specified
// in ctx.To match with the label selectors specified in the egress rules
// contained within r.
func (r *rule) canReachEgress(ctx *SearchContext, state *traceState) api.Decision {

	if !r.EndpointSelector.Matches(ctx.From) {
		state.unSelectRule(ctx, ctx.From, r)
		return api.Undecided
	}

	state.selectRule(ctx, r)

	for _, r := range r.Egress {
		for _, sel := range r.ToRequires {
			//fmt.Printf("r.ToRequires: %s\n", r.ToRequires)
			ctx.PolicyTrace("    Requires from labels %+v", sel)
			if !sel.Matches(ctx.To) {
				ctx.PolicyTrace("-     Labels %v not found\n", ctx.To)
				state.constrainedRules++
				return api.Denied
			}
			ctx.PolicyTrace("+     Found all required labels\n")
		}
	}

	// Separate loop is needed as failure to meet ToRequires always takes
	// precedence over ToEndpoints.
	for _, r := range r.Egress {
		for _, sel := range r.ToEndpoints {
			ctx.PolicyTrace("    Allows to labels %+v", sel)
			if sel.Matches(ctx.To) {
				ctx.PolicyTrace("      Found all required labels")
				if len(r.ToPorts) == 0 {
					ctx.PolicyTrace("+       No L4 restrictions\n")
					state.matchedRules++
					return api.Allowed
				}
				ctx.PolicyTrace("        Rule restricts traffic from specific L4 destinations; deferring policy decision to L4 policy stage\n")
			} else {
				ctx.PolicyTrace("      Labels %v not found\n", ctx.To)
			}
		}
	}

	for _, entitySelector := range r.toEntities {
		if entitySelector.Matches(ctx.To) {
			ctx.PolicyTrace("+     Found all required labels to match entity %s\n", entitySelector.String())
			state.matchedRules++
			return api.Allowed
		}
	}

	return api.Undecided
}

func (r *rule) canReachEntities(ctx *SearchContext, state *traceState) api.Decision {
	for _, entitySelector := range r.toEntities {
		if entitySelector.Matches(ctx.To) {
			ctx.PolicyTrace("+     Found all required labels to match entity %s\n", entitySelector.String())
			state.matchedRules++
			return api.Allowed
		}
	}

	return api.Undecided
}

func mergeL4Egress(ctx *SearchContext, toEndpoints []api.EndpointSelector, portRules []api.PortRule,
	ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	if len(portRules) == 0 {
		ctx.PolicyTrace("    No L4 %s rules\n", policymap.Egress)
		return 0, nil
	}

	found := 0
	var err error

	for _, r := range portRules {
		if toEndpoints != nil {
			ctx.PolicyTrace("    Allows %s port %v from endpoints %v\n", policymap.Egress, r.Ports, toEndpoints)
		} else {
			ctx.PolicyTrace("    Allows %s port %v\n", policymap.Egress, r.Ports)
		}

		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
		}

		l3match := false
		if ctx.To != nil && toEndpoints != nil {
			for _, labels := range toEndpoints {
				if labels.Matches(ctx.To) {
					l3match = true
					break
				}
			}
			if l3match == false {
				ctx.PolicyTrace("      Labels %s not found", ctx.To)
				continue
			}
		}
		ctx.PolicyTrace("      Found all required labels")

		for _, p := range r.Ports {
			var cnt int
			if p.Protocol != api.ProtoAny {
				cnt, err = mergeL4EgressPort(ctx, toEndpoints, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err = mergeL4EgressPort(ctx, toEndpoints, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeL4EgressPort(ctx, toEndpoints, r, p, api.ProtoUDP, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			}
		}
	}

	return found, nil
}

func mergeL4EgressPort(ctx *SearchContext, endpoints []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(proto)
	filter, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4EgressFilter(endpoints, r, p, proto, ruleLabels)
		return 1, nil
	}
	l4Filter := CreateL4EgressFilter(endpoints, r, p, proto, ruleLabels)
	if l4Filter.L7Parser != "" {
		if filter.L7Parser == "" {
			filter.L7Parser = l4Filter.L7Parser
		} else if l4Filter.L7Parser != filter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", l4Filter.L7Parser, filter.L7Parser)
			return 0, fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", l4Filter.L7Parser, filter.L7Parser)
		}
	}

	if filter.addEndpoints(endpoints) && r.NumRules() == 0 {
		// skip this policy as it is already covered and it does not contain L7 rules
		return 1, nil
	}

	for hash, newL7Rules := range l4Filter.L7RulesPerEp {
		if ep, ok := filter.L7RulesPerEp[hash]; ok {
			switch {
			case len(newL7Rules.HTTP) > 0:
				if len(ep.Kafka) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return 0, fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.HTTP {
					if !newRule.Exists(ep) {
						ep.HTTP = append(ep.HTTP, newRule)
					}
				}
			case len(newL7Rules.Kafka) > 0:
				if len(ep.HTTP) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return 0, fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.Kafka {
					if !newRule.Exists(ep) {
						ep.Kafka = append(ep.Kafka, newRule)
					}
				}
			default:
				ctx.PolicyTrace("   No L7 rules to merge.\n")
			}
			filter.L7RulesPerEp[hash] = ep
		} else {
			filter.L7RulesPerEp[hash] = newL7Rules
		}
	}

	filter.DerivedFromRules = append(filter.DerivedFromRules, ruleLabels)
	resMap[key] = filter
	return 1, nil
}

func (r *rule) resolveL4EgressPolicy(ctx *SearchContext, state *traceState, result *L4Policy) (*L4Policy, error) {

	if !r.EndpointSelector.Matches(ctx.From) {
		state.unSelectRule(ctx, ctx.From, r)
		return nil, nil
	}

	state.selectRule(ctx, r)
	found := 0

	if len(r.Egress) == 0 {
		ctx.PolicyTrace("    No L4 rules\n")
	}
	for _, egressRule := range r.Egress {
		cnt, err := mergeL4Egress(ctx, egressRule.ToEndpoints, egressRule.ToPorts, r.Rule.Labels.DeepCopy(), result.Egress)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			found += cnt
		}
	}

	if found > 0 {
		return result, nil
	}

	return nil, nil
}
