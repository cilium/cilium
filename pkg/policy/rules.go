// Copyright 2016-2019 Authors of Cilium
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
	"strconv"

	"github.com/cilium/cilium/pkg/policy/api"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) wildcardL3L4Rules(ingress bool, l4Policy L4PolicyMap, requirements []v1.LabelSelectorRequirement, selectorCache *SelectorCache) {
	// Duplicate L3-only rules into wildcard L7 rules.
	for _, r := range rules {
		if ingress {
			for _, rule := range r.Ingress {
				// Non-label-based rule. Ignore.
				if !rule.AllowsWildcarding() {
					continue
				}

				fromEndpoints := rule.GetSourceEndpointSelectorsWithRequirements(requirements)
				ruleLabels := r.Rule.Labels.DeepCopy()

				// L3-only rule.
				if len(rule.ToPorts) == 0 && len(fromEndpoints) > 0 {
					wildcardL3L4Rule(api.ProtoTCP, 0, fromEndpoints, ruleLabels, l4Policy, selectorCache)
					wildcardL3L4Rule(api.ProtoUDP, 0, fromEndpoints, ruleLabels, l4Policy, selectorCache)
				} else {
					// L4-only or L3-dependent L4 rule.
					//
					// "fromEndpoints" may be empty here, which indicates that all L3 peers should
					// be selected. If so, add the wildcard selector.
					if len(fromEndpoints) == 0 {
						fromEndpoints = append(fromEndpoints, api.WildcardEndpointSelector)
					}
					for _, toPort := range rule.ToPorts {
						// L3/L4-only rule
						if toPort.Rules.IsEmpty() {
							for _, p := range toPort.Ports {
								// Already validated via PortRule.Validate().
								port, _ := strconv.ParseUint(p.Port, 0, 16)
								wildcardL3L4Rule(p.Protocol, int(port), fromEndpoints, ruleLabels, l4Policy, selectorCache)
							}
						}
					}
				}
			}
		} else {
			for _, rule := range r.Egress {
				// Non-label-based rule. Ignore.
				if !rule.AllowsWildcarding() {
					continue
				}

				toEndpoints := rule.GetDestinationEndpointSelectorsWithRequirements(requirements)
				ruleLabels := r.Rule.Labels.DeepCopy()

				// L3-only rule.
				if len(rule.ToPorts) == 0 && len(toEndpoints) > 0 {
					wildcardL3L4Rule(api.ProtoTCP, 0, toEndpoints, ruleLabels, l4Policy, selectorCache)
					wildcardL3L4Rule(api.ProtoUDP, 0, toEndpoints, ruleLabels, l4Policy, selectorCache)
				} else {
					// L4-only or L3-dependent L4 rule.
					//
					// "toEndpoints" may be empty here, which indicates that all L3 peers should
					// be selected. If so, add the wildcard selector.
					if len(toEndpoints) == 0 {
						toEndpoints = append(toEndpoints, api.WildcardEndpointSelector)
					}
					for _, toPort := range rule.ToPorts {
						// L3/L4-only rule
						if toPort.Rules.IsEmpty() {
							for _, p := range toPort.Ports {
								// Already validated via PortRule.Validate().
								port, _ := strconv.ParseUint(p.Port, 0, 16)
								wildcardL3L4Rule(p.Protocol, int(port), toEndpoints, ruleLabels, l4Policy, selectorCache)
							}
						}
					}
				}
			}
		}
	}
}

func (rules ruleSlice) resolveL4IngressPolicy(policyCtx PolicyContext, ctx *SearchContext) (L4PolicyMap, error) {
	result := L4PolicyMap{}

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving ingress policy for %+v\n", ctx.To)

	state := traceState{}
	var matchedRules ruleSlice
	var requirements []v1.LabelSelectorRequirement

	// Iterate over all FromRequires which select ctx.To. These requirements
	// will be appended to each EndpointSelector's MatchExpressions in
	// each FromEndpoints for all ingress rules. This ensures that FromRequires
	// is taken into account when evaluating policy at L4.
	for _, r := range rules {
		if ctx.rulesSelect || r.EndpointSelector.Matches(ctx.To) {
			matchedRules = append(matchedRules, r)
			for _, ingressRule := range r.Ingress {
				for _, requirement := range ingressRule.FromRequires {
					requirements = append(requirements, requirement.ConvertToLabelSelectorRequirementSlice()...)
				}
			}
		}
	}

	// Only dealing with matching rules from now on. Mark it in the ctx
	oldRulesSelect := ctx.rulesSelect
	ctx.rulesSelect = true

	for _, r := range matchedRules {
		found, err := r.resolveIngressPolicy(policyCtx, ctx, &state, result, requirements)
		if err != nil {
			return nil, err
		}
		state.ruleID++
		if found != nil {
			state.matchedRules++
		}
	}

	matchedRules.wildcardL3L4Rules(true, result, requirements, policyCtx.GetSelectorCache())

	state.trace(len(rules), ctx)

	// Restore ctx in case caller uses it again.
	ctx.rulesSelect = oldRulesSelect

	return result, nil
}

func (rules ruleSlice) resolveL4EgressPolicy(policyCtx PolicyContext, ctx *SearchContext) (L4PolicyMap, error) {
	result := L4PolicyMap{}

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving egress policy for %+v\n", ctx.From)

	state := traceState{}
	var matchedRules ruleSlice
	var requirements []v1.LabelSelectorRequirement

	// Iterate over all ToRequires which select ctx.To. These requirements will
	// be appended to each EndpointSelector's MatchExpressions in each
	// ToEndpoints for all egress rules. This ensures that ToRequires is
	// taken into account when evaluating policy at L4.
	for _, r := range rules {
		if ctx.rulesSelect || r.EndpointSelector.Matches(ctx.From) {
			matchedRules = append(matchedRules, r)
			for _, egressRule := range r.Egress {
				for _, requirement := range egressRule.ToRequires {
					requirements = append(requirements, requirement.ConvertToLabelSelectorRequirementSlice()...)
				}
			}
		}
	}

	// Only dealing with matching rules from now on. Mark it in the ctx
	oldRulesSelect := ctx.rulesSelect
	ctx.rulesSelect = true

	for i, r := range matchedRules {
		state.ruleID = i
		found, err := r.resolveEgressPolicy(policyCtx, ctx, &state, result, requirements)
		if err != nil {
			return nil, err
		}
		state.ruleID++
		if found != nil {
			state.matchedRules++
		}
	}

	matchedRules.wildcardL3L4Rules(false, result, requirements, policyCtx.GetSelectorCache())

	state.trace(len(rules), ctx)

	// Restore ctx in case caller uses it again.
	ctx.rulesSelect = oldRulesSelect

	return result, nil
}

func (rules ruleSlice) resolveCIDRPolicy(ctx *SearchContext) *CIDRPolicy {
	result := NewCIDRPolicy()

	ctx.PolicyTrace("Resolving L3 (CIDR) policy for %+v\n", ctx.To)

	state := traceState{}
	for _, r := range rules {
		r.resolveCIDRPolicy(ctx, &state, result)
		state.ruleID++
	}

	state.trace(len(rules), ctx)
	return result
}

// updateEndpointsCaches iterates over a given list of rules to update the cache
// within the rule which determines whether or not the given identity is
// selected by that rule. If a rule in the list does select said identity, it is
// added to epSet. Note that epSet can be shared across goroutines!
// Returns whether the endpoint was selected by one of the rules, or if the
// endpoint is nil.
func (rules ruleSlice) updateEndpointsCaches(ep Endpoint) (bool, error) {
	if ep == nil {
		return false, fmt.Errorf("cannot update caches in rules because endpoint is nil")
	}
	id := ep.GetID16()
	securityIdentity, err := ep.GetSecurityIdentity()
	if err != nil {
		return false, fmt.Errorf("cannot update caches in rules for endpoint %d because it is being deleted: %s", id, err)
	}

	if securityIdentity == nil {
		return false, fmt.Errorf("cannot update caches in rules for endpoint %d because it has a nil identity", id)
	}
	endpointSelected := false
	for _, r := range rules {
		// Update the matches cache of each rule, and note if
		// the ep is selected by any of them.
		if ruleMatches := r.matches(securityIdentity); ruleMatches {
			endpointSelected = true
		}
	}

	return endpointSelected, nil
}
