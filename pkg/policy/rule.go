// Copyright 2016-2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

type rule struct {
	api.Rule

	// mutex protects everything below it (i.e., not the rule itself).
	mutex lock.RWMutex

	// localRuleConsumers is the set of the numeric identifiers which this rule
	// selects which are node-local (e.g., Endpoint).
	localRuleConsumers map[uint16]*identity.Identity

	// processedConsumers tracks which consumers have been 'processed' - that is,
	// it determines whether the consumer has actually been processed in relation
	// to this rule. It does *not* encode whether the rule selects the consumer;
	// that is what localRuleConsumers is for.
	processedConsumers map[uint16]struct{}
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

func mergeL4Port(ctx *SearchContext, endpoints []api.EndpointSelector, existingFilter, filterToMerge *L4Filter) error {
	// Handle cases where filter we are merging new rule with, new rule itself
	// allows all traffic on L3, or both rules allow all traffic on L3.
	//
	// Case 1: either filter selects all endpoints, which means that this filter
	// can now simply select all endpoints.
	if existingFilter.AllowsAllAtL3() || filterToMerge.AllowsAllAtL3() {
		existingFilter.Endpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		existingFilter.allowsAllAtL3 = true
	} else {
		// Case 2: no wildcard endpoint selectors in existing filter or in filter
		// to merge, so just append endpoints.
		existingFilter.Endpoints = append(existingFilter.Endpoints, endpoints...)
	}

	// Merge the L7-related data from the arguments provided to this function
	// with the existing L7-related data already in the filter.
	if filterToMerge.L7Parser != ParserTypeNone {
		if existingFilter.L7Parser == ParserTypeNone {
			existingFilter.L7Parser = filterToMerge.L7Parser
		} else if filterToMerge.L7Parser != existingFilter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", filterToMerge.L7Parser, existingFilter.L7Parser)
			return fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", filterToMerge.L7Parser, existingFilter.L7Parser)
		}
	}

	for hash, newL7Rules := range filterToMerge.L7RulesPerEp {
		if ep, ok := existingFilter.L7RulesPerEp[hash]; ok {
			switch {
			case len(newL7Rules.HTTP) > 0:
				if len(ep.Kafka) > 0 || len(ep.DNS) > 0 || ep.L7Proto != "" {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.HTTP {
					if !newRule.Exists(ep) {
						ep.HTTP = append(ep.HTTP, newRule)
					}
				}
			case len(newL7Rules.Kafka) > 0:
				if len(ep.HTTP) > 0 || len(ep.DNS) > 0 || ep.L7Proto != "" {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.Kafka {
					if !newRule.Exists(ep) {
						ep.Kafka = append(ep.Kafka, newRule)
					}
				}
			case newL7Rules.L7Proto != "":
				if len(ep.Kafka) > 0 || len(ep.HTTP) > 0 || len(ep.DNS) > 0 || (ep.L7Proto != "" && ep.L7Proto != newL7Rules.L7Proto) {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}
				if ep.L7Proto == "" {
					ep.L7Proto = newL7Rules.L7Proto
				}

				for _, newRule := range newL7Rules.L7 {
					if !newRule.Exists(ep) {
						ep.L7 = append(ep.L7, newRule)
					}
				}
			case len(newL7Rules.DNS) > 0:
				if len(ep.HTTP) > 0 || len(ep.Kafka) > 0 || len(ep.L7) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.DNS {
					if !newRule.Exists(ep) {
						ep.DNS = append(ep.DNS, newRule)
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
	return nil
}

// mergeL4IngressPort merges all rules which share the same port & protocol that
// select a given set of endpoints. It updates the L4Filter mapped to by the specified
// port and protocol with the contents of the provided PortRule. If the rule
// being merged has conflicting L7 rules with those already in the provided
// L4PolicyMap for the specified port-protocol tuple, it returns an error.
//
// If any rules contain L7 rules that overlap with the endpointsWithL3Override,
// then for the endpoints with L3 override, the L7 rules will be translated
// into L7 wildcards (ie, traffic will be forwarded to the proxy for endpoints
// matching those labels, but the proxy will allow all such traffic).
func mergeL4IngressPort(ctx *SearchContext, endpoints []api.EndpointSelector, endpointsWithL3Override []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(proto)
	existingFilter, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4IngressFilter(endpoints, endpointsWithL3Override, r, p, proto, ruleLabels)
		return 1, nil
	}

	// Create a new L4Filter based off of the arguments provided to this function
	// for merging with the filter which is already in the policy map.
	filterToMerge := CreateL4IngressFilter(endpoints, endpointsWithL3Override, r, p, proto, ruleLabels)

	if err := mergeL4Port(ctx, endpoints, &existingFilter, &filterToMerge); err != nil {
		return 0, err
	}
	existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	resMap[key] = existingFilter
	return 1, nil
}

func mergeL4Ingress(ctx *SearchContext, rule api.IngressRule, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	if len(rule.ToPorts) == 0 {
		ctx.PolicyTrace("    No L4 %s rules\n", trafficdirection.Ingress)
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

	// Daemon options may induce L3 allows for host/world. In this case, if
	// we find any L7 rules matching host/world then we need to turn any L7
	// restrictions on these endpoints into L7 allow-all so that the
	// traffic is always allowed, but is also always redirected through the
	// proxy
	endpointsWithL3Override := []api.EndpointSelector{}
	if option.Config.AlwaysAllowLocalhost() {
		endpointsWithL3Override = append(endpointsWithL3Override, api.ReservedEndpointSelectors[labels.IDNameHost])
		if option.Config.HostAllowsWorld {
			endpointsWithL3Override = append(endpointsWithL3Override, api.ReservedEndpointSelectors[labels.IDNameWorld])
		}
	}

	for _, r := range rule.ToPorts {
		ctx.PolicyTrace("    Allows %s port %v from endpoints %v\n", trafficdirection.Ingress, r.Ports, fromEndpoints)
		if r.Rules != nil && r.Rules.L7Proto != "" {
			ctx.PolicyTrace("      l7proto: \"%s\"\n", r.Rules.L7Proto)
		}
		if !r.Rules.IsEmpty() {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
			for _, l7 := range r.Rules.Kafka {
				ctx.PolicyTrace("        %+v\n", l7)
			}
			for _, l7 := range r.Rules.L7 {
				ctx.PolicyTrace("        %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeL4IngressPort(ctx, fromEndpoints, endpointsWithL3Override, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err := mergeL4IngressPort(ctx, fromEndpoints, endpointsWithL3Override, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeL4IngressPort(ctx, fromEndpoints, endpointsWithL3Override, r, p, api.ProtoUDP, ruleLabels, resMap)
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
func (r *rule) resolveL4IngressPolicy(ctx *SearchContext, state *traceState, result *L4Policy, requirements []v1.LabelSelectorRequirement) (*L4Policy, error) {
	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.To) {
			state.unSelectRule(ctx, ctx.To, r)
			return nil, nil
		}
	}

	state.selectRule(ctx, r)
	found := 0

	if len(r.Ingress) == 0 {
		ctx.PolicyTrace("    No L4 ingress rules\n")
	}
	for _, ingressRule := range r.Ingress {
		ruleCopy := ingressRule

		// For each FromEndpoints in each ingress rule, add requirements, which
		// is a flattened list of all EndpointSelectors from all FromRequires
		// from rules which select the labels in ctx.To. This ensures that
		// FromRequires is taken into account even if it isn't part of the current
		// rule over which we are iterating.
		if len(requirements) > 0 {
			// Create a deep copy of the rule, as we are going to modify FromEndpoints
			// with requirementsSelector. We don't want to modify the rule itself
			// in the policy repository.
			ruleCopy = *ingressRule.DeepCopy()
			// Update each EndpointSelector in FromEndpoints to contain requirements.
			for idx := range ruleCopy.FromEndpoints {
				ruleCopy.FromEndpoints[idx].MatchExpressions = append(ruleCopy.FromEndpoints[idx].MatchExpressions, requirements...)
				ruleCopy.FromEndpoints[idx].SyncRequirementsWithLabelSelector()
			}
		}

		cnt, err := mergeL4Ingress(ctx, ruleCopy, r.Rule.Labels.DeepCopy(), result.Ingress)
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

// resolveCIDRPolicy inserts the CIDRs from the specified rule into result if
// the rule corresponds to the current SearchContext. It returns the resultant
// CIDRPolicy containing the added ingress and egress CIDRs. If no CIDRs are
// added to result, a nil CIDRPolicy is returned.
func (r *rule) resolveCIDRPolicy(ctx *SearchContext, state *traceState, result *CIDRPolicy) *CIDRPolicy {
	// Don't select rule if it doesn't apply to the given context.
	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.To) {
			state.unSelectRule(ctx, ctx.To, r)
			return nil
		}
	}

	state.selectRule(ctx, r)
	found := 0

	for _, ingressRule := range r.Ingress {
		// TODO (ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, ingressRule.FromCIDR...)
		allCIDRs = append(allCIDRs, api.ComputeResultantCIDRSet(ingressRule.FromCIDRSet)...)

		// CIDR + L4 rules are handled via mergeL4Ingress(),
		// skip them here.
		if len(allCIDRs) > 0 && len(ingressRule.ToPorts) > 0 {
			continue
		}

		if cnt := mergeCIDR(ctx, "Ingress", allCIDRs, r.Labels, &result.Ingress); cnt > 0 {
			found += cnt
		}
	}

	// CIDR egress policy is used for visibility of desired state in
	// the API and for determining which prefix lengths are available,
	// however it does not determine the actual CIDRs in the BPF maps
	// for allowing traffic by CIDR!
	for _, egressRule := range r.Egress {
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, egressRule.ToCIDR...)
		allCIDRs = append(allCIDRs, api.ComputeResultantCIDRSet(egressRule.ToCIDRSet)...)

		// Unlike the Ingress policy which only counts L3 policy in
		// this function, we count the CIDR+L4 policy in the
		// desired egress CIDR policy here as well. This ensures
		// proper computation of IPcache prefix lengths.
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

	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.To) {
			state.unSelectRule(ctx, ctx.To, r)
			return api.Undecided
		}
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

	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.From) {
			state.unSelectRule(ctx, ctx.From, r)
			return api.Undecided
		}
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
		ctx.PolicyTrace("    No L4 %s rules\n", trafficdirection.Egress)
		return 0, nil
	}

	toEndpoints := rule.GetDestinationEndpointSelectors()
	found := 0

	for _, r := range rule.ToPorts {
		ctx.PolicyTrace("    Allows %s port %v to endpoints %v\n", trafficdirection.Egress, r.Ports, toEndpoints)
		if r.Rules != nil && r.Rules.L7Proto != "" {
			ctx.PolicyTrace("      l7proto: \"%s\"\n", r.Rules.L7Proto)
		}
		if !r.Rules.IsEmpty() {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
			for _, l7 := range r.Rules.Kafka {
				ctx.PolicyTrace("        %+v\n", l7)
			}
			for _, l7 := range r.Rules.L7 {
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

	if err := mergeL4Port(ctx, endpoints, &existingFilter, &filterToMerge); err != nil {
		return 0, err
	}
	existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	resMap[key] = existingFilter
	return 1, nil
}

func (r *rule) resolveL4EgressPolicy(ctx *SearchContext, state *traceState, result *L4Policy, requirements []v1.LabelSelectorRequirement) (*L4Policy, error) {
	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.From) {
			state.unSelectRule(ctx, ctx.From, r)
			return nil, nil
		}
	}

	state.selectRule(ctx, r)
	found := 0

	if len(r.Egress) == 0 {
		ctx.PolicyTrace("    No L4 rules\n")
	}
	for _, egressRule := range r.Egress {
		ruleCopy := egressRule
		// For each ToEndpoints in each egress rule, add the requirements, which
		// is a flattened list of all EndpointSelectors from all ToRequires
		// from rules which select the labels in ctx.From. This ensures that
		// ToRequires is taken into account even if it isn't part of the current
		// rule over which we are iterating.
		if len(requirements) > 0 {
			// Create a deep copy of the rule, as we are going to modify
			// ToEndpoints with requirements; we don't want to modify the rule
			// in the repository.
			ruleCopy = *egressRule.DeepCopy()
			for idx := range ruleCopy.ToEndpoints {
				// Update each EndpointSelector in ToEndpoints to contain
				// requirements.
				ruleCopy.ToEndpoints[idx].MatchExpressions = append(ruleCopy.ToEndpoints[idx].MatchExpressions, requirements...)
				ruleCopy.ToEndpoints[idx].SyncRequirementsWithLabelSelector()
			}
		}
		cnt, err := mergeL4Egress(ctx, ruleCopy, r.Rule.Labels.DeepCopy(), result.Egress)
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
