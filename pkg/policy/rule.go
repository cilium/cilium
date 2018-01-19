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

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
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

func (policy *L4Filter) addFromEndpoints(fromEndpoints []api.EndpointSelector) bool {

	if len(policy.FromEndpoints) == 0 && len(fromEndpoints) > 0 {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: fromEndpoints,
			"policy":                   policy,
		}).Debug("skipping L4 filter as the endpoints are already covered.")
		return true
	}

	if len(policy.FromEndpoints) > 0 && len(fromEndpoints) == 0 {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: fromEndpoints,
			"policy":                   policy,
		}).Debug("new L4 filter applies to all endpoints, making the policy more permissive.")
		policy.FromEndpoints = nil
	}

	policy.FromEndpoints = append(policy.FromEndpoints, fromEndpoints...)
	return false
}

func mergeL4Port(ctx *SearchContext, fromEndpoints []api.EndpointSelector, r api.PortRule, p api.PortProtocol,
	dir string, proto api.L4Proto, resMap L4PolicyMap) (int, error) {

	key := p.Port + "/" + string(proto)
	v, ok := resMap[key]
	if !ok {
		resMap[key] = CreateL4Filter(fromEndpoints, r, p, dir, proto)
		return 1, nil
	}
	l4Filter := CreateL4Filter(fromEndpoints, r, p, dir, proto)
	if l4Filter.L7Parser != "" {
		if v.L7Parser == "" {
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

	if len(portRules) == 0 {
		ctx.PolicyTrace("    No L4 rules\n")
		return 0, nil
	}

	found := 0
	var err error

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

		l3match := false
		if ctx.From != nil && fromEndpoints != nil {
			for _, labels := range fromEndpoints {
				if labels.Matches(ctx.From) {
					l3match = true
					break
				}
			}
			if l3match == false {
				ctx.PolicyTrace("      Labels %s not found", ctx.From)
				continue
			}
		}
		ctx.PolicyTrace("      Found all required labels")

		for _, p := range r.Ports {
			var cnt int
			if p.Protocol != api.ProtoAny {
				cnt, err = mergeL4Port(ctx, fromEndpoints, r, p, dir, p.Protocol, resMap)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err = mergeL4Port(ctx, fromEndpoints, r, p, dir, api.ProtoTCP, resMap)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeL4Port(ctx, fromEndpoints, r, p, dir, api.ProtoUDP, resMap)
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

	if !ctx.EgressL4Only {
		if len(r.Ingress) == 0 {
			ctx.PolicyTrace("    No L4 rules\n")
		}
		for _, r := range r.Ingress {
			cnt, err := mergeL4(ctx, "Ingress", r.FromEndpoints, r.ToPorts, result.Ingress)
			if err != nil {
				return nil, err
			}
			found += cnt
		}
	}

	if !ctx.IngressL4Only {
		if len(r.Egress) == 0 {
			ctx.PolicyTrace("    No L4 rules\n")
		}
		for _, r := range r.Egress {
			cnt, err := mergeL4(ctx, "Egress", nil, r.ToPorts, result.Egress)
			if err != nil {
				return nil, err
			}
			found += cnt
		}
	}

	if found > 0 {
		return result, nil
	}

	return nil, nil
}

func mergeL3(ctx *SearchContext, dir string, ipRules []api.CIDR, resMap *L3PolicyMap) int {
	strCIDRs := []string{}

	for _, r := range ipRules {
		strCIDRs = append(strCIDRs, string(r))
	}
	ctx.PolicyTrace("  Allows %s IPs %s\n", dir, ipRules)

	return resMap.Insert(strCIDRs)
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

func cidrsToIPNets(cidrs []api.CIDR) (v4Nets, v6Nets []*net.IPNet) {
	v4Nets = []*net.IPNet{}
	v6Nets = []*net.IPNet{}
	for _, v := range cidrs {
		_, netToParse, err := net.ParseCIDR(string(v))
		// ParseCIDR will result in an error if CIDR is an IP without
		// a mask, which is valid in Cilium.
		if err != nil {
			ip := net.ParseIP(string(v))
			// ip cannot be nil as it has already been validated. Check if IP
			// is of v4 or v6 to determine mask size.
			var mask net.IPMask
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			} else {
				mask = net.CIDRMask(32, 32)
			}
			netToParse = &net.IPNet{IP: ip, Mask: mask}
		}
		if netToParse.IP.To4() != nil {
			v4Nets = append(v4Nets, netToParse)
		} else {
			v6Nets = append(v6Nets, netToParse)
		}
	}
	return
}

func (r *rule) resolveL3Policy(ctx *SearchContext, state *traceState, result *L3Policy) *L3Policy {
	
	if !r.EndpointSelector.Matches(ctx.To) {
		state.unSelectRule(ctx, r)
		return nil
	}

	state.selectRule(ctx, r)
	found := 0

	// L3 Ingress
	if !ctx.EgressL4Only {
		allIngressCIDRs := []api.CIDR{}
		for _, r := range r.Ingress {
			// Create list of CIDRs containing all CIDRs which we allow ingress from.
			// It contains the resultant list of CIDRs from which traffic is allowed
			// after excluding cidrs in FromCIDRSet for each rule.
			allIngressCIDRs = append(allIngressCIDRs, append(r.FromCIDR, computeResultantCIDRSet(r.FromCIDRSet)...)...)
		}

		found += mergeL3(ctx, "Ingress", allIngressCIDRs, &result.Ingress)
	}

	// L3 Egress
	if !ctx.IngressL4Only {
		allEgressCIDRs := []api.CIDR{}
		for _, r := range r.Egress {
			allEgressCIDRs = append(allEgressCIDRs, append(r.ToCIDR, computeResultantCIDRSet(r.ToCIDRSet)...)...)
		}
		found += mergeL3(ctx, "Egress", allEgressCIDRs, &result.Egress)
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
