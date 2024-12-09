// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) resolveL4IngressPolicy(policyCtx PolicyContext, ctx *SearchContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving ingress policy for %+v\n", ctx.To)

	state := traceState{}

	// matchedRules must be constructed before setting
	// ctx.ruleSelect to true for the call to (*rule).resolveL4IgressPolicy
	var matchedRules ruleSlice
	for _, r := range rules {
		if ctx.rulesSelect || r.getSelector().Matches(ctx.To) {
			matchedRules = append(matchedRules, r)
		}
	}

	oldRulesSelect := ctx.rulesSelect
	ctx.rulesSelect = true

	for _, r := range matchedRules {
		_, err := r.resolveIngressPolicy(policyCtx, ctx, &state, result)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}

	state.trace(len(rules), ctx)

	// Restore ctx in case caller uses it again.
	ctx.rulesSelect = oldRulesSelect

	return result, nil
}

func (rules ruleSlice) resolveL4EgressPolicy(policyCtx PolicyContext, ctx *SearchContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving egress policy for %+v\n", ctx.From)

	state := traceState{}

	// matchedRules must be constructed before setting
	// ctx.ruleSelect to true for the call to (*rule).resolveL4EgressPolicy
	var matchedRules ruleSlice
	for _, r := range rules {
		if ctx.rulesSelect || r.getSelector().Matches(ctx.From) {
			matchedRules = append(matchedRules, r)
		}
	}

	// Only dealing with matching rules from now on. Mark it in the ctx
	oldRulesSelect := ctx.rulesSelect
	ctx.rulesSelect = true

	for _, r := range matchedRules {
		_, err := r.resolveEgressPolicy(policyCtx, ctx, &state, result)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}

	state.trace(len(rules), ctx)

	// Restore ctx in case caller uses it again.
	ctx.rulesSelect = oldRulesSelect

	return result, nil
}

// AsPolicyRules return the internal policyapi.Rule objects as a policyapi.Rules object
func (rules ruleSlice) AsPolicyRules() policyapi.Rules {
	policyRules := make(policyapi.Rules, 0, len(rules))
	for _, r := range rules {
		policyRules = append(policyRules, &r.Rule)
	}
	return policyRules
}
