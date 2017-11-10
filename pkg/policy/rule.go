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
	"strconv"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	log "github.com/sirupsen/logrus"
)

const (
	dirIngress = "Ingress"
	dirEgress  = "Egress"
)

type rule struct {
	api.Rule

	fromEntities []api.EndpointSelector
	toEntities   []api.EndpointSelector
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

// sanitize has a side effect of populating the fromEntities and toEntities
// slices to avoid superfluent map accesses
func (r *rule) sanitize() error {
	if r == nil || r.EndpointSelector.LabelSelector == nil {
		return fmt.Errorf("nil rule")
	}

	if err := r.Rule.Sanitize(); err != nil {
		return err
	}

	if len(r.EndpointSelector.MatchLabels) == 0 &&
		len(r.EndpointSelector.MatchExpressions) == 0 {
		return fmt.Errorf("empty EndpointSelector")
	}

	// resetting entity selector slices
	r.fromEntities = []api.EndpointSelector{}
	r.toEntities = []api.EndpointSelector{}
	entities := []api.Entity{}

	ingressEntityCounter := 0
	for _, rule := range r.Ingress {
		entities = append(entities, rule.FromEntities...)
		ingressEntityCounter += len(rule.FromEntities)
	}

	for _, rule := range r.Egress {
		entities = append(entities, rule.ToEntities...)
	}

	for j, entity := range entities {
		selector, ok := api.EntitySelectorMapping[entity]
		if !ok {
			return fmt.Errorf("unsupported entity: %s", entity)
		}

		if j < ingressEntityCounter {
			r.fromEntities = append(r.fromEntities, selector)
		} else {
			r.toEntities = append(r.toEntities, selector)
		}
	}

	return nil
}

func (l4 *L4Filter) addFromEndpoints(fromEndpoints []api.EndpointSelector) bool {
	if len(l4.FromEndpoints) == 0 {
		log.WithFields(log.Fields{
			logfields.EndpointSelector: fromEndpoints,
			"policy":                   l4,
		}).Debug("Skipping L4 filter as the endpoints are already covered")
		return true
	}

	if len(fromEndpoints) == 0 {
		// new policy is more permissive than the existing policy
		// use a more permissive one
		l4.FromEndpoints = nil
		return false
	}

	l4.FromEndpoints = append(l4.FromEndpoints, fromEndpoints...)
	return false
}

func mergeIngressVisibilityPort(ctx *SearchContext, p api.PortProtocol, l7Parser api.L7ParserType,
	resMap L4PolicyMap, visMap L7VisibilityMap, defaultAllow bool) (int, error) {

	// Already validated via IngressVisibilityRule.sanitize().
	l4Port, _ := strconv.ParseUint(p.Port, 0, 16)

	key := p.Port + "/" + string(p.Protocol)
	v, ok := resMap[key]
	if !ok {
		if defaultAllow {
			// If the policy enablement mode is "default" and there are no ingress or egress rules,
			// all traffic is allowed. If there are no L4 rules matching this port, synthesize one which
			// allows all endpoints to reach this port.
			ctx.PolicyTraceVerbose("   Default allow mode; creating Ingress rule for port %v with L7 parser %s\n", p, l7Parser)
			v = L4Filter{
				Port:     int(l4Port),
				Protocol: p.Protocol,
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(),
				},
				L7RulesPerEp: make(L7DataMap),
				Ingress:      true,
			}
		} else {
			// Try to find a rule allowing any port.
			anyKey := "0/" + string(api.ProtoAny)
			anyV, ok := resMap[anyKey]
			if ok {
				// All ports are accessible. We can synthesize a rule for the port accessible from the
				// same endpoints.
				ctx.PolicyTraceVerbose("   Any port rule(s) found; creating Ingress rule for port %v with L7 parser %s\n", p, l7Parser)
				v = L4Filter{
					Port:          int(l4Port),
					Protocol:      p.Protocol,
					FromEndpoints: anyV.FromEndpoints,
					L7RulesPerEp:  make(L7DataMap),
					Ingress:       true,
				}
			} else {
				// The L4 port is not accessible. Ignore any visibility rule for that port.
				ctx.PolicyTraceVerbose("   No L4 rule found for port %v, and policy is not default allow; "+
					"ignoring visibility rule with L7 parser %s\n", p, l7Parser)
				return 0, nil
			}
		}
	}

	if v.IsRedirect() {
		// There is already at least one L7 rule for that L4 port.
		ctx.PolicyTraceVerbose("   Existing L7 rule for port %v with L7 parser %s \n", p, v.L7Parser)

		// Check whether the L7 parser is the same as for the visibility rule.
		if l7Parser != v.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", l7Parser, v.L7Parser)
			return 0, fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", l7Parser, v.L7Parser)
		}

		// Right now, if there is any L7 rule, all traffic to the port is already redirected to the L7 proxy.
		// So there is no need to create a new rule to redirect to the L7 proxy for visibility.
		return 0, nil
	}

	// Create an implicit allow-all rule to allow the traffic and redirect it to the L7 proxy.
	v.L7Parser = l7Parser
	var rules api.L7Rules
	switch l7Parser {
	case api.ParserTypeHTTP:
		rules.HTTP = append(rules.HTTP, api.PortRuleHTTP{})
	case api.ParserTypeKafka:
		rules.Kafka = append(rules.Kafka, api.PortRuleKafka{})
	}

	// Only add the L7 rule for the from-endpoints that are not yet associated with an L7 rule.
	v.L7RulesPerEp.addRulesForEndpoints(rules, v.FromEndpoints)

	ctx.PolicyTrace("  Visibility into %s port %v\n", dirIngress, p)

	// Report as active visibility rule.
	visMap[key] = L7VisibilityRule{
		Port:       uint16(l4Port),
		Protocol:   p.Protocol,
		L7Protocol: l7Parser,
	}

	resMap[key] = v
	return 1, nil
}

func mergeL4Port(ctx *SearchContext, fromEndpoints []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	dir string, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(p.Protocol)
	v, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4Filter(fromEndpoints, r, p, dir)
		return 1, nil
	}
	l4Filter := CreateL4Filter(fromEndpoints, r, p, dir)
	if l4Filter.IsRedirect() {
		if !v.IsRedirect() {
			v.L7Parser = l4Filter.L7Parser
		} else if l4Filter.L7Parser != v.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", l4Filter.L7Parser, v.L7Parser)
			return 0, fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", l4Filter.L7Parser, v.L7Parser)
		}
	}

	if l4Filter.L7RedirectPort != 0 {
		if v.L7RedirectPort == 0 {
			v.L7RedirectPort = l4Filter.L7RedirectPort
		} else if l4Filter.L7RedirectPort != v.L7RedirectPort {
			ctx.PolicyTrace("   Merge conflict: mismatching redirect ports %d/%d\n", l4Filter.L7RedirectPort, v.L7RedirectPort)
			return 0, fmt.Errorf("Cannot merge conflicting redirect ports (%d/%d)", l4Filter.L7RedirectPort, v.L7RedirectPort)
		}
	}

	if v.addFromEndpoints(fromEndpoints) && r.NumRules() == 0 {
		// skip this policy as it is already covered and it does not contain L7 rules
		resMap[key] = v
		return 1, nil
	}

	for hash, newL7Rules := range l4Filter.L7RulesPerEp {
		if ep, ok := v.L7RulesPerEp[hash]; ok {
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
			v.L7RulesPerEp[hash] = ep
		} else {
			v.L7RulesPerEp[hash] = newL7Rules
		}
	}

	resMap[key] = v
	return 1, nil
}

func mergeL4(ctx *SearchContext, dir string, fromEndpoints []api.EndpointSelector, portRules []api.PortRule,
	resMap L4PolicyMap) (int, error) {

	found := 0
	var err error

	l3match := false
	if ctx.From != nil && fromEndpoints != nil {
		for _, labels := range fromEndpoints {
			if labels.Matches(ctx.From) {
				l3match = true
				break
			}
		}
	}

	// If the labels are not found, disable tracing of ports.
	portCtx := *ctx
	if !l3match {
		portCtx.Trace = TRACE_DISABLED
	}

	// No ports are specified, so any port are allowed.
	// Create an explicit filter with special port/protocol "0/ANY".
	if len(portRules) == 0 {
		if fromEndpoints != nil {
			ctx.PolicyTrace("  Allows %s any port from endpoints %v\n", dir, fromEndpoints)
		} else {
			ctx.PolicyTrace("  Allows %s any port\n", dir)
		}

		if !l3match {
			ctx.PolicyTrace("      Labels %s not found", ctx.From)
		} else {
			ctx.PolicyTrace("      Found all required labels")
		}

		p := api.PortProtocol{
			Port:     "0",
			Protocol: api.ProtoAny,
		}
		r := api.PortRule{
			Ports: []api.PortProtocol{p},
		}
		var cnt int
		cnt, err = mergeL4Port(&portCtx, fromEndpoints, r, p, dir, resMap)
		if err != nil {
			return found, err
		}
		found += cnt
	}

	for _, r := range portRules {
		if fromEndpoints != nil {
			ctx.PolicyTrace("    Allows %s port %v from endpoints %v\n", dir, r.Ports, fromEndpoints)
		} else {
			ctx.PolicyTrace("    Allows %s port %v\n", dir, r.Ports)
		}

		if r.RedirectPort != 0 {
			ctx.PolicyTrace("      Redirect-To: %d\n", r.RedirectPort)
		}

		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("        %+v\n", l7)
			}
		}

		if !l3match {
			ctx.PolicyTrace("      Labels %s not found", ctx.From)
		} else {
			ctx.PolicyTrace("      Found all required labels")
		}

		for _, p := range r.Ports {
			var cnt int
			if p.Protocol != api.ProtoAny {
				cnt, err = mergeL4Port(&portCtx, fromEndpoints, r, p, dir, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err = mergeL4Port(&portCtx, fromEndpoints, r, api.PortProtocol{Port: p.Port, Protocol: api.ProtoTCP}, dir, resMap)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeL4Port(&portCtx, fromEndpoints, r, api.PortProtocol{Port: p.Port, Protocol: api.ProtoUDP}, dir, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			}
		}
	}

	return found, nil
}

// mergeIngressVisibility merges visibility rules into the given maps.
// Returns the number of ingress rules that have been created as a result of the merge.
func mergeIngressVisibility(ctx *SearchContext, rule api.IngressVisibilityRule, resMap L4PolicyMap, visMap L7VisibilityMap,
	defaultAllow bool) (int, error) {
	found := 0

	for _, p := range rule.ToPorts {
		var cnt int
		var err error
		if p.Protocol != api.ProtoAny {
			cnt, err = mergeIngressVisibilityPort(ctx, p, rule.L7Protocol, resMap, visMap, defaultAllow)
			if err != nil {
				return found, err
			}
			found += cnt
		} else {
			cnt, err = mergeIngressVisibilityPort(ctx, api.PortProtocol{Port: p.Port, Protocol: api.ProtoTCP},
				rule.L7Protocol, resMap, visMap, defaultAllow)
			if err != nil {
				return found, err
			}
			found += cnt

			cnt, err = mergeIngressVisibilityPort(ctx, api.PortProtocol{Port: p.Port, Protocol: api.ProtoUDP},
				rule.L7Protocol, resMap, visMap, defaultAllow)
			if err != nil {
				return found, err
			}
			found += cnt
		}
	}

	return found, nil
}

func (state *traceState) selectRule(ctx *SearchContext, r *rule) {
	ctx.PolicyTrace("* Rule %s: selected\n", r)
	state.selectedRules++
}

func (state *traceState) unSelectRule(ctx *SearchContext, r *rule) {
	ctx.PolicyTraceVerbose("  Rule %s: did not select %+v\n", r, ctx.To)
}

func (r *rule) resolveL4Policy(ctx *SearchContext, state *traceState, result *L4Policy) (*L4Policy, error) {
	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, r)
		return nil, nil
	}

	state.selectRule(ctx, r)
	found := 0

	// Always resolve both ingress and egress, in order to always generate the same
	// L4Policy. This is required for resolving visibility rules. But disable tracing
	// for the rules that were not requested for tracing.
	ingressCtx := *ctx
	if ctx.EgressL4Only {
		ingressCtx.Trace = TRACE_DISABLED
	}
	egressCtx := *ctx
	if ctx.IngressL4Only {
		egressCtx.Trace = TRACE_DISABLED
	}

	if len(r.Ingress) == 0 {
		ingressCtx.PolicyTrace("    No Ingress L4 rules\n")
	}
	for _, r := range r.Ingress {
		cnt, err := mergeL4(&ingressCtx, "Ingress", r.FromEndpoints, r.ToPorts, result.Ingress)
		if err != nil {
			return nil, err
		}
		if !ctx.EgressL4Only {
			found += cnt
		}
	}

	if len(r.Egress) == 0 {
		egressCtx.PolicyTrace("    No Egress L4 rules\n")
	}
	for _, r := range r.Egress {
		cnt, err := mergeL4(&egressCtx, "Egress", nil, r.ToPorts, result.Egress)
		if err != nil {
			return nil, err
		}
		if !ctx.IngressL4Only {
			found += cnt
		}
	}

	if found > 0 {
		return result, nil
	}

	return nil, nil
}

// allowAllRule is a L4 rule that allows all ingress & egress L4 traffic.
var allowAllRule = rule{
	Rule: api.Rule{
		EndpointSelector: api.NewESFromLabels(),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(),
				},
			},
		},
		Egress: []api.EgressRule{
			{},
		},
	},
}

func (r *rule) resolveIngressVisibility(ctx *SearchContext, state *traceState, result *L4Policy) error {
	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, r)
		return nil
	}

	ctx.PolicyTrace("* Rule %s: selected\n", r)

	defaultAllow := len(result.Ingress) == 0 && len(result.Egress) == 0 &&
		GetPolicyEnabled() == "default" // endpoint.DefaultEnforcement

	found := 0

	// Always resolve visibility rules, even if ctx.EgressL4Only is true, because the synthesis of
	// ingress rules may change the enablement of policy enforcement, even at egress. Cf. below.
	for _, r := range r.IngressVisibility {
		cnt, err := mergeIngressVisibility(ctx, r, result.Ingress, result.IngressVisibility, defaultAllow)
		if err != nil {
			return err
		}
		found += cnt
	}

	if found > 0 {
		// If the policy enforcement mode is "default", and one or more visibility rules are matching,
		// policy enforcement becomes enabled.
		// Cf. daemon/policy.go's Daemon.EnableEndpointPolicyEnforcement.
		// If there were no ingress or egress rules, this means that the policy enforcement changed from
		// disabled / "default allow" to enabled / "default deny" because of the visibility rules.
		// Synthesize "allow all" rules at ingress and egress to retain the disabled / "default allow"
		// semantics.
		if defaultAllow {
			ctx.PolicyTrace("    Default allow-all ingress/egress rule created\n")
			_, err := allowAllRule.resolveL4Policy(ctx, state, result)
			if err != nil {
				return err
			}
		}

		return nil
	}

	ctx.PolicyTrace("    No active ingress visibility rules\n")
	return nil
}

func mergeL3(ctx *SearchContext, dir string, ipRules []api.CIDR, resMap *L3PolicyMap) int {
	found := 0

	for _, r := range ipRules {
		strCIDR := string(r)
		ctx.PolicyTrace("  Allows %s IP %s\n", dir, strCIDR)

		found += resMap.Insert(strCIDR)
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

func (r *rule) resolveL3Policy(ctx *SearchContext, state *traceState, result *L3Policy) *L3Policy {
	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, r)
		return nil
	}

	state.selectRule(ctx, r)
	found := 0

	for _, r := range r.Ingress {
		// TODO (ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, r.FromCIDR...)

		allCIDRs = append(allCIDRs, computeResultantCIDRSet(r.FromCIDRSet)...)

		found += mergeL3(ctx, "Ingress", allCIDRs, &result.Ingress)
	}

	for _, r := range r.Egress {
		// TODO(ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, r.ToCIDR...)

		allCIDRs = append(allCIDRs, computeResultantCIDRSet(r.ToCIDRSet)...)

		found += mergeL3(ctx, "Egress", allCIDRs, &result.Egress)
	}

	if found > 0 {
		return result
	}

	ctx.PolicyTrace("    No L3 rules\n")
	return nil
}

func (r *rule) canReach(ctx *SearchContext, state *traceState) api.Decision {
	entitiesDecision := r.canReachEntities(ctx, state)

	if !r.EndpointSelector.Matches(ctx.To) {
		if entitiesDecision == api.Undecided {
			state.unSelectRule(ctx, r)
		} else {
			state.selectRule(ctx, r)
		}
		return entitiesDecision
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
	// precedence over FromEndpoints
	for _, r := range r.Ingress {
		for _, sel := range r.FromEndpoints {
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

	for _, entitySelector := range r.fromEntities {
		if entitySelector.Matches(ctx.From) {
			ctx.PolicyTrace("+     Found all required labels to match entity %s\n", entitySelector.String())
			state.matchedRules++
			return api.Allowed
		}

	}

	return entitiesDecision
}

func (r *rule) canReachEntities(ctx *SearchContext, state *traceState) api.Decision {
	for _, entitySelector := range r.toEntities {
		if entitySelector.Matches(ctx.To) {
			ctx.PolicyTrace("+     Found all required labels to match entity %s\n", entitySelector.String())
			state.matchedRules++
			return api.Allowed
		}
	}

	return api.Undecided
}
