// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"cmp"
	"slices"

	"github.com/cilium/cilium/pkg/policy/types"
)

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) resolveL4Policy(policyCtx PolicyContext) (L4PolicyMap, error) {
	result := NewL4PolicyMap()

	state := traceState{}
	for _, r := range rules {
		err := result.resolveL4Policy(policyCtx, &state, r)
		if err != nil {
			return nil, err
		}
		state.ruleID++
	}

	state.trace(len(rules), policyCtx)

	return result, nil
}

// Always sort matched rules to get a stable policy order.
// It's not the order per se that is important, just that it's always in the same order when the
// elements are the same. In most cases this should be a small list so the overhead should be pretty minimal.
// This is very useful for subsystems like the dnsproxy that can reuse the same regex during recompilation
// if the list of FQDNs is the same.
func (rules ruleSlice) sort() {
	slices.SortFunc(rules, func(a, b *rule) int {
		if sign := cmp.Compare(a.key.resource, b.key.resource); sign != 0 {
			return sign
		}
		return cmp.Compare(a.key.idx, b.key.idx)
	})
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

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

func (state *traceState) trace(rules int, policyCtx PolicyContext) {
	policyCtx.PolicyTrace("%d/%d rules selected\n", state.selectedRules, rules)
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

func (state *traceState) selectRule(policyCtx PolicyContext, r *rule) {
	policyCtx.PolicyTrace("* Rule %s: selected\n", r)
	state.selectedRules++
}
