// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) resolveL4IngressPolicy(policyCtx PolicyContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	policyCtx.PolicyTrace("Resolving ingress policy")

	state := traceState{}
	var requirements, requirementsDeny []slim_metav1.LabelSelectorRequirement

	// Iterate over all FromRequires which select ctx.To. These requirements
	// will be appended to each EndpointSelector's MatchExpressions in
	// each FromEndpoints for all ingress rules. This ensures that FromRequires
	// is taken into account when evaluating policy at L4.
	for _, r := range rules {
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

	for _, r := range rules {
		err := r.resolveIngressPolicy(policyCtx, &state, result, requirements, requirementsDeny)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}
	result.FinalizePerSelectorPolicies()

	state.trace(len(rules), policyCtx)

	return result, nil
}

func (rules ruleSlice) resolveL4EgressPolicy(policyCtx PolicyContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	policyCtx.PolicyTrace("resolving egress policy")

	state := traceState{}
	var requirements, requirementsDeny []slim_metav1.LabelSelectorRequirement

	// Iterate over all ToRequires which select ctx.To. These requirements will
	// be appended to each EndpointSelector's MatchExpressions in each
	// ToEndpoints for all egress rules. This ensures that ToRequires is
	// taken into account when evaluating policy at L4.
	for _, r := range rules {
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

	for i, r := range rules {
		state.ruleID = i
		err := r.resolveEgressPolicy(policyCtx, &state, result, requirements, requirementsDeny)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}
	result.FinalizePerSelectorPolicies()

	state.trace(len(rules), policyCtx)

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

// traceState is an internal structure used to collect information
// while determining policy decision
type traceState struct {
	// selectedRules is the number of rules with matching EndpointSelector
	selectedRules int

	// matchedRules is the number of rules that have allowed traffic
	matchedRules int

	// matchedDenyRules is the number of rules that have denied traffic
	matchedDenyRules int

	// constrainedRules counts how many "FromRequires" constraints are
	// unsatisfied
	constrainedRules int

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

func (state *traceState) trace(rules int, policyCtx PolicyContext) {
	policyCtx.PolicyTrace("%d/%d rules selected\n", state.selectedRules, rules)
	if state.constrainedRules > 0 {
		policyCtx.PolicyTrace("Found unsatisfied FromRequires constraint\n")
	} else {
		if state.matchedRules > 0 {
			policyCtx.PolicyTrace("Found allow rule\n")
		} else {
			policyCtx.PolicyTrace("Found no allow rule\n")
		}
		if state.matchedDenyRules > 0 {
			policyCtx.PolicyTrace("Found deny rule\n")
		} else {
			policyCtx.PolicyTrace("Found no deny rule\n")
		}
	}
}

func (state *traceState) selectRule(policyCtx PolicyContext, r *rule) {
	policyCtx.PolicyTrace("* Rule %s: selected\n", r)
	state.selectedRules++
}
