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
	"strconv"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func (rules ruleSlice) canReachIngressRLocked(ctx *SearchContext) api.Decision {
	decision := api.Undecided
	state := traceState{}

loop:
	for i, r := range rules {
		state.ruleID = i
		switch r.canReachIngress(ctx, &state) {
		// The rule contained a constraint which was not met, this
		// connection is not allowed
		case api.Denied:
			decision = api.Denied
			break loop

			// The rule allowed the connection but a later rule may impose
			// additional constraints, so we store the decision but allow
			// it to be overwritten by an additional requirement
		case api.Allowed:
			decision = api.Allowed
		}
	}

	state.trace(rules, ctx)

	return decision
}

func (rules ruleSlice) wildcardL3L4Rules(ctx *SearchContext, ingress bool, l4Policy L4PolicyMap) {
	// Duplicate L3-only rules into wildcard L7 rules.
	for _, r := range rules {
		if ingress {
			if !ctx.rulesSelect {
				if !r.EndpointSelector.Matches(ctx.To) {
					continue
				}
			}
			for _, rule := range r.Ingress {
				// Non-label-based rule. Ignore.
				if !rule.IsLabelBased() {
					continue
				}

				fromEndpoints := rule.GetSourceEndpointSelectors()
				ruleLabels := r.Rule.Labels.DeepCopy()

				// L3-only rule.
				if len(rule.ToPorts) == 0 {
					wildcardL3L4Rule(api.ProtoTCP, 0, fromEndpoints, ruleLabels, l4Policy)
					wildcardL3L4Rule(api.ProtoUDP, 0, fromEndpoints, ruleLabels, l4Policy)
				} else {
					for _, toPort := range rule.ToPorts {
						// L3/L4-only rule
						if toPort.Rules.IsEmpty() {
							for _, p := range toPort.Ports {
								// Already validated via PortRule.Validate().
								port, _ := strconv.ParseUint(p.Port, 0, 16)
								wildcardL3L4Rule(p.Protocol, int(port), fromEndpoints, ruleLabels, l4Policy)
							}
						}
					}
				}
			}
		} else {
			if !ctx.rulesSelect {
				if !r.EndpointSelector.Matches(ctx.From) {
					continue
				}
			}
			for _, rule := range r.Egress {
				// Non-label-based rule. Ignore.
				if !rule.IsLabelBased() {
					continue
				}

				toEndpoints := rule.GetDestinationEndpointSelectors()
				ruleLabels := r.Rule.Labels.DeepCopy()

				// L3-only rule.
				if len(rule.ToPorts) == 0 {
					wildcardL3L4Rule(api.ProtoTCP, 0, toEndpoints, ruleLabels, l4Policy)
					wildcardL3L4Rule(api.ProtoUDP, 0, toEndpoints, ruleLabels, l4Policy)
				} else {
					for _, toPort := range rule.ToPorts {
						// L3/L4-only rule
						if toPort.Rules.IsEmpty() {
							for _, p := range toPort.Ports {
								// Already validated via PortRule.Validate().
								port, _ := strconv.ParseUint(p.Port, 0, 16)
								wildcardL3L4Rule(p.Protocol, int(port), toEndpoints, ruleLabels, l4Policy)
							}
						}
					}
				}
			}
		}
	}
}

func (rules ruleSlice) resolveL4IngressPolicy(ctx *SearchContext, revision uint64) (*L4Policy, error) {
	result := NewL4Policy()

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving ingress port policy for %+v\n", ctx.To)

	state := traceState{}
	var requirements []v1.LabelSelectorRequirement

	// Iterate over all FromRequires which select ctx.To. These requirements
	// will be appended to each EndpointSelector's MatchExpressions in
	// each FromEndpoints for all ingress rules. This ensures that FromRequires
	// is taken into account when evaluating policy at L4.
	if !ctx.skipL4RequirementsAggregation {
		for _, r := range rules {
			for _, ingressRule := range r.Ingress {
				if r.EndpointSelector.Matches(ctx.To) {
					for _, requirement := range ingressRule.FromRequires {
						requirements = append(requirements, requirement.ConvertToLabelSelectorRequirementSlice()...)
					}
				}
			}
		}
	}

	for _, r := range rules {
		found, err := r.resolveL4IngressPolicy(ctx, &state, result, requirements)
		if err != nil {
			return nil, err
		}
		state.ruleID++
		if found != nil {
			state.matchedRules++
		}
	}

	rules.wildcardL3L4Rules(ctx, true, result.Ingress)
	result.Revision = revision

	state.trace(rules, ctx)
	return result, nil
}

func (rules ruleSlice) resolveL4EgressPolicy(ctx *SearchContext, revision uint64) (*L4Policy, error) {
	result := NewL4Policy()

	ctx.PolicyTrace("\n")
	ctx.PolicyTrace("Resolving egress port policy for %+v\n", ctx.To)

	var requirements []v1.LabelSelectorRequirement

	// Iterate over all ToRequires which select ctx.To. These requirements will
	// be appended to each EndpointSelector's MatchExpressions in each
	// ToEndpoints for all ingress rules. This ensures that ToRequires is
	// taken into account when evaluating policy at L4.
	if !ctx.skipL4RequirementsAggregation {
		for _, r := range rules {
			for _, egressRule := range r.Egress {
				if r.EndpointSelector.Matches(ctx.From) {
					for _, requirement := range egressRule.ToRequires {
						requirements = append(requirements, requirement.ConvertToLabelSelectorRequirementSlice()...)
					}
				}
			}
		}
	}

	state := traceState{}
	for i, r := range rules {
		state.ruleID = i
		found, err := r.resolveL4EgressPolicy(ctx, &state, result, requirements)
		if err != nil {
			return nil, err
		}
		state.ruleID++
		if found != nil {
			state.matchedRules++
		}
	}

	rules.wildcardL3L4Rules(ctx, false, result.Egress)
	result.Revision = revision

	state.trace(rules, ctx)
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

	state.trace(rules, ctx)
	return result
}

func (rules ruleSlice) canReachEgressRLocked(egressCtx *SearchContext) api.Decision {
	egressDecision := api.Undecided
	egressState := traceState{}

egressLoop:
	for i, r := range rules {
		egressState.ruleID = i
		switch r.canReachEgress(egressCtx, &egressState) {
		// The rule contained a constraint which was not met, this
		// connection is not allowed
		case api.Denied:
			egressDecision = api.Denied
			break egressLoop

			// The rule allowed the connection but a later rule may impose
			// additional constraints, so we store the decision but allow
			// it to be overwritten by an additional requirement
		case api.Allowed:
			egressDecision = api.Allowed
		}
	}

	egressState.trace(rules, egressCtx)

	return egressDecision
}

// AnalyzeWhetherRulesSelectEndpoints iterates over a given list of rules to
// update the cache within the rule which determines whether or not the given
// identity is selected by that rule. If a rule in the list does select said
// identity, it is added to epIDSet. Signals to the given WaitGroup that
// all rules have been parsed in relation to said identity.
func (rules ruleSlice) AnalyzeWhetherRulesSelectEndpoint(id uint16, securityIdentity *identity.Identity, epIDSet *EndpointIDSet, wg *sync.WaitGroup) {
	for _, r := range rules {
		r.mutex.Lock()
		var ruleMatches bool

		if _, ok := r.processedConsumers[id]; ok {
			if _, ok := r.localRuleConsumers[id]; ok {
				ruleMatches = true
			}
		} else {
			ruleMatches = r.EndpointSelector.Matches(securityIdentity.LabelArray)
		}
		if ruleMatches {
			epIDSet.Mutex.Lock()
			epIDSet.Eps[id] = struct{}{}
			epIDSet.Mutex.Unlock()
			r.localRuleConsumers[id] = securityIdentity
		}
		r.processedConsumers[id] = struct{}{}
		r.mutex.Unlock()
	}
	// Work done for calculating change for this endpoint in relation to list of
	// rules.
	wg.Done()
}
