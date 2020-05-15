// Copyright 2016-2020 Authors of Cilium
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

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) resolveL4IngressPolicy(policyCtx PolicyContext, ctx *SearchContext) (L4PolicyMap, error) {
	result := L4PolicyMap{}

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving ingress policy for %+v\n", ctx.To)

	state := traceState{}
	var matchedRules ruleSlice
	var requirements []slim_metav1.LabelSelectorRequirement

	// Iterate over all FromRequires which select ctx.To. These requirements
	// will be appended to each EndpointSelector's MatchExpressions in
	// each FromEndpoints for all ingress rules. This ensures that FromRequires
	// is taken into account when evaluating policy at L4.
	for _, r := range rules {
		if ctx.rulesSelect || r.getSelector().Matches(ctx.To) {
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
	var requirements []slim_metav1.LabelSelectorRequirement

	// Iterate over all ToRequires which select ctx.To. These requirements will
	// be appended to each EndpointSelector's MatchExpressions in each
	// ToEndpoints for all egress rules. This ensures that ToRequires is
	// taken into account when evaluating policy at L4.
	for _, r := range rules {
		if ctx.rulesSelect || r.getSelector().Matches(ctx.From) {
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
		// NodeSelector can only match nodes, EndpointSelector only pods.
		if (r.NodeSelector.LabelSelector != nil) != ep.IsHost() {
			continue
		}
		// Update the matches cache of each rule, and note if
		// the ep is selected by any of them.
		if ruleMatches := r.matches(securityIdentity); ruleMatches {
			endpointSelected = true
		}
	}

	return endpointSelected, nil
}
