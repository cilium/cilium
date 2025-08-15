// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import "github.com/cilium/cilium/pkg/policy/types"

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) resolveL4IngressPolicy(policyCtx PolicyContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	policyCtx.PolicyTrace("Resolving ingress policy")

	state := traceState{}

	for _, r := range rules {
		err := r.resolveIngressPolicy(policyCtx, &state, result)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}

	state.trace(len(rules), policyCtx)

	return result, nil
}

func (rules ruleSlice) resolveL4EgressPolicy(policyCtx PolicyContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	policyCtx.PolicyTrace("resolving egress policy")

	state := traceState{}

	for i, r := range rules {
		state.ruleID = i
		err := r.resolveEgressPolicy(policyCtx, &state, result)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}

	state.trace(len(rules), policyCtx)

	return result, nil
}

// AsPolicyEntries return the internal PolicyEntry objects as a PolicyEntries object
func (rules ruleSlice) AsPolicyEntries() types.PolicyEntries {
	policyRules := make(types.PolicyEntries, 0, len(rules))
	for _, r := range rules {
		policyRules = append(policyRules, &r.PolicyEntry)
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
