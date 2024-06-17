// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/cilium/cilium/pkg/identity"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
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
	var requirements, requirementsDeny []slim_metav1.LabelSelectorRequirement

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
			for _, ingressRule := range r.IngressDeny {
				for _, requirement := range ingressRule.FromRequires {
					requirementsDeny = append(requirementsDeny, requirement.ConvertToLabelSelectorRequirementSlice()...)
				}
			}
		}
	}

	// Only dealing with matching rules from now on. Mark it in the ctx
	oldRulesSelect := ctx.rulesSelect
	ctx.rulesSelect = true

	for _, r := range matchedRules {
		_, err := r.resolveIngressPolicy(policyCtx, ctx, &state, result, requirements, requirementsDeny)
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
	result := L4PolicyMap{}

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving egress policy for %+v\n", ctx.From)

	state := traceState{}
	var matchedRules ruleSlice
	var requirements, requirementsDeny []slim_metav1.LabelSelectorRequirement

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
			for _, egressRule := range r.EgressDeny {
				for _, requirement := range egressRule.ToRequires {
					requirementsDeny = append(requirementsDeny, requirement.ConvertToLabelSelectorRequirementSlice()...)
				}
			}
		}
	}

	// Only dealing with matching rules from now on. Mark it in the ctx
	oldRulesSelect := ctx.rulesSelect
	ctx.rulesSelect = true

	for i, r := range matchedRules {
		state.ruleID = i
		_, err := r.resolveEgressPolicy(policyCtx, ctx, &state, result, requirements, requirementsDeny)
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

// matchesSubject determines whether any rule in a set of rules selects the given
// security identity as a subject (i.e. non-peer).
func (rules ruleSlice) matchesSubject(securityIdentity *identity.Identity) bool {
	for _, r := range rules {
		if r.matchesSubject(securityIdentity) {
			return true
		}
	}

	return false
}

// AsPolicyRules return the internal policyapi.Rule objects as a policyapi.Rules object
func (rules ruleSlice) AsPolicyRules() policyapi.Rules {
	policyRules := make(policyapi.Rules, 0, len(rules))
	for _, r := range rules {
		policyRules = append(policyRules, &r.Rule)
	}
	return policyRules
}
