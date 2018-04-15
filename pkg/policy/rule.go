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
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

type rule struct {
	api.Rule
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

// mergeL4IngressPort merges all rules which share the same port & protocol that
// select a given set of endpoints. It updates the L4Filter mapped to by the specified
// port and protocol with the contents of the provided PortRule. If the rule
// being merged has conflicting L7 rules with those already in the provided
// L4PolicyMap for the specified port-protocol tuple, it returns an error.
func mergeL4IngressPort(ctx *SearchContext, endpoints []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(proto)
	existingFilter, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4IngressFilter(endpoints, r, p, proto, ruleLabels)
		return 1, nil
	}

	// Create a new L4Filter based off of the arguments provided to this function
	// for merging with the filter which is already in the policy map.
	filterToMerge := CreateL4IngressFilter(endpoints, r, p, proto, ruleLabels)

	// Handle cases where filter we are merging new rule with, or new rule itself
	// allows all traffic on L3.
	//
	// Existing filter selects all endpoints, so don't add new endpoints.
	if existingFilter.AllowsAllAtL3() && len(filterToMerge.Endpoints) > 0 {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: filterToMerge.Endpoints,
			"policy":                   existingFilter,
		}).Debug("skipping L4 filter as the endpoints are already covered")

		// Existing L4Filter already selects all endpoints; if there are no L7 rules
		// to add from the new rule, then we can just exit because the rule is as
		// permissive as possible at L3, the L4 information is already contained
		// within the filter, and there is no L7 metadata to add to the filter.
		if r.NumRules() == 0 {
			existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
			resMap[key] = existingFilter
			return 1, nil
		}
	} else {
		// If new rule allows all endpoints, then allow all endpoints.
		if len(existingFilter.Endpoints) > 0 && filterToMerge.AllowsAllAtL3() {
			log.WithFields(logrus.Fields{
				logfields.EndpointSelector: filterToMerge.Endpoints,
				"policy":                   existingFilter,
			}).Debug("new L4 filter applies to all endpoints, making the policy more permissive")

			existingFilter.Endpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}

			// If new rule allows all endpoints and does have L7 rules, update
			// filter's L7Parser.
			if filterToMerge.L7Parser != ParserTypeNone && existingFilter.L7Parser == ParserTypeNone {
				existingFilter.L7Parser = filterToMerge.L7Parser
			}
		} else {
			existingFilter.Endpoints = append(existingFilter.Endpoints, endpoints...)
		}
	}

	// Now, determine whether we allow all on L4.
	// Rule we are merging with existing L4Filter has no L7 rules, but applies
	// to the same L4 port-protocol tuple, which *does* have L7 rules. If a rule
	// applying to the same port/protocol has no L7 rules, then that equates to
	// allowing all on L7, so just remove existing L7-related metadata for this
	// port-proto tuple. Or, if we already have a filter which allows all L4, yet
	// are trying to add a rule which restricts on L7, do not restrict on L7.
	if r.NumRules() == 0 || existingFilter.L7Parser == ParserTypeNone {
		for k := range existingFilter.L7RulesPerEp {
			delete(existingFilter.L7RulesPerEp, k)
		}
		existingFilter.L7Parser = ParserTypeNone
		existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
		resMap[key] = existingFilter
		return 1, nil
	}

	// Merge the L7-related data from the arguments provided to this function
	// with the existing L7-related data already in the filter.
	if filterToMerge.L7Parser != ParserTypeNone {
		if existingFilter.L7Parser == ParserTypeNone {
			existingFilter.L7Parser = filterToMerge.L7Parser
		} else if filterToMerge.L7Parser != existingFilter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", filterToMerge.L7Parser, existingFilter.L7Parser)
			return 0, fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", filterToMerge.L7Parser, existingFilter.L7Parser)
		}
	}

	for hash, newL7Rules := range filterToMerge.L7RulesPerEp {
		if ep, ok := existingFilter.L7RulesPerEp[hash]; ok {
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
			existingFilter.L7RulesPerEp[hash] = ep
		} else {
			existingFilter.L7RulesPerEp[hash] = newL7Rules
		}
	}

	existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	resMap[key] = existingFilter
	return 1, nil
}

func mergeL4Ingress(ctx *SearchContext, rule api.IngressRule, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	if len(rule.ToPorts) == 0 {
		ctx.PolicyTrace("    No L4 %s rules\n", policymap.Ingress)
		return 0, nil
	}

	fromEndpoints := rule.GetSourceEndpointSelectors()
	found := 0

	if ctx.From != nil && len(fromEndpoints) > 0 {
		if !fromEndpoints.Matches(ctx.From) {
			ctx.PolicyTrace("    Labels %s not found", ctx.From)
			return 0, nil
		}
	}

	ctx.PolicyTrace("    Found all required labels")

	for _, r := range rule.ToPorts {
		ctx.PolicyTrace("    Allows %s port %v from endpoints %v\n", policymap.Ingress, r.Ports, fromEndpoints)
		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeL4IngressPort(ctx, fromEndpoints, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err := mergeL4IngressPort(ctx, fromEndpoints, r, p, api.ProtoTCP, ruleLabels, resMap)
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
		cnt, err := mergeL4Ingress(ctx, ingressRule, r.Rule.Labels.DeepCopy(), result.Ingress)
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

		if cnt := mergeCIDR(ctx, "Ingress", allCIDRs, r.Labels, &result.Ingress); cnt > 0 {
			found += cnt
		}
	}

	for _, egressRule := range r.Egress {
		// TODO(ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, egressRule.ToCIDR...)
		allCIDRs = append(allCIDRs, computeResultantCIDRSet(egressRule.ToCIDRSet)...)

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
	// precedence over FromEndpoints and FromEntities
	for _, r := range r.Ingress {
		for _, sel := range r.GetSourceEndpointSelectors() {
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
	// precedence over ToEndpoints and ToEntities
	for _, r := range r.Egress {
		for _, sel := range r.GetDestinationEndpointSelectors() {
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

	return api.Undecided
}

func mergeL4Egress(ctx *SearchContext, rule api.EgressRule, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	if len(rule.ToPorts) == 0 {
		ctx.PolicyTrace("    No L4 %s rules\n", policymap.Egress)
		return 0, nil
	}

	toEndpoints := rule.GetDestinationEndpointSelectors()
	found := 0

	for _, r := range rule.ToPorts {
		ctx.PolicyTrace("    Allows %s port %v to endpoints %v\n", policymap.Egress, r.Ports, toEndpoints)

		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeL4EgressPort(ctx, toEndpoints, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err := mergeL4EgressPort(ctx, toEndpoints, r, p, api.ProtoTCP, ruleLabels, resMap)
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

// mergeL4EgressPort merges all rules which share the same port & protocol that
// select a given set of endpoints. It updates the L4Filter mapped to by the specified
// port and protocol with the contents of the provided PortRule. If the rule
// being merged has conflicting L7 rules with those already in the provided
// L4PolicyMap for the specified port-protocol tuple, it returns an error.
func mergeL4EgressPort(ctx *SearchContext, endpoints []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(proto)
	existingFilter, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4EgressFilter(endpoints, r, p, proto, ruleLabels)
		return 1, nil
	}

	// Create a new L4Filter based off of the arguments provided to this function
	// for merging with the filter which is already in the policy map.
	filterToMerge := CreateL4EgressFilter(endpoints, r, p, proto, ruleLabels)

	// Handle cases where filter we are merging new rule with, or new rule itself
	// allows all traffic on L3.
	//
	// Existing filter selects all endpoints, so don't add new endpoints.
	if existingFilter.AllowsAllAtL3() && len(filterToMerge.Endpoints) > 0 {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: filterToMerge.Endpoints,
			"policy":                   existingFilter,
		}).Debug("skipping L4 filter as the endpoints are already covered")

		// Existing L4Filter already selects all endpoints; if there are no L7 rules
		// to add from the new rule, then we can just exit because the rule is as
		// permissive as possible at L3, the L4 information is already contained
		// within the filter, and there is no L7 metadata to add to the filter.
		if r.NumRules() == 0 {
			existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
			resMap[key] = existingFilter
			return 1, nil
		}
	} else {
		// If new rule allows all endpoints, then allow all endpoints.
		if len(existingFilter.Endpoints) > 0 && filterToMerge.AllowsAllAtL3() {
			log.WithFields(logrus.Fields{
				logfields.EndpointSelector: filterToMerge.Endpoints,
				"policy":                   existingFilter,
			}).Debug("new L4 filter applies to all endpoints, making the policy more permissive")

			existingFilter.Endpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}

			// If new rule allows all endpoints and does have L7 rules, update
			// filter's L7Parser.
			if filterToMerge.L7Parser != ParserTypeNone && existingFilter.L7Parser == ParserTypeNone {
				existingFilter.L7Parser = filterToMerge.L7Parser
			}
		} else {
			existingFilter.Endpoints = append(existingFilter.Endpoints, endpoints...)
		}
	}

	// Now, determine whether we allow all on L4.
	// Rule we are merging with existing L4Filter has no L7 rules, but applies
	// to the same L4 port-protocol tuple, which *does* have L7 rules. If a rule
	// applying to the same port/protocol has no L7 rules, then that equates to
	// allowing all on L7, so just remove existing L7-related metadata for this
	// port-proto tuple. Or, if we already have a filter which allows all L4, yet
	// are trying to add a rule which restricts on L7, do not restrict on L7.
	if r.NumRules() == 0 || existingFilter.L7Parser == ParserTypeNone {
		for k := range existingFilter.L7RulesPerEp {
			delete(existingFilter.L7RulesPerEp, k)
		}
		existingFilter.L7Parser = ParserTypeNone
		existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
		resMap[key] = existingFilter
		return 1, nil
	}

	// Merge the L7-related data from the arguments provided to this function
	// with the existing L7-related data already in the filter.
	if filterToMerge.L7Parser != ParserTypeNone {
		if existingFilter.L7Parser == ParserTypeNone {
			existingFilter.L7Parser = filterToMerge.L7Parser
		} else if filterToMerge.L7Parser != existingFilter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", filterToMerge.L7Parser, existingFilter.L7Parser)
			return 0, fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", filterToMerge.L7Parser, existingFilter.L7Parser)
		}
	}

	for hash, newL7Rules := range filterToMerge.L7RulesPerEp {
		if ep, ok := existingFilter.L7RulesPerEp[hash]; ok {
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
			existingFilter.L7RulesPerEp[hash] = ep
		} else {
			existingFilter.L7RulesPerEp[hash] = newL7Rules
		}
	}

	existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	resMap[key] = existingFilter
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
		cnt, err := mergeL4Egress(ctx, egressRule, r.Rule.Labels.DeepCopy(), result.Egress)
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
