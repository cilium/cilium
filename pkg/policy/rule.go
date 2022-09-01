// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/api/kafka"
)

type rule struct {
	api.Rule

	metadata *ruleMetadata
}

type ruleMetadata struct {
	// mutex protects all fields in this type.
	Mutex lock.RWMutex

	// IdentitySelected is a cache that maps from an identity to whether
	// this rule selects that identity.
	IdentitySelected map[identity.NumericIdentity]bool
}

func newRuleMetadata() *ruleMetadata {
	return &ruleMetadata{
		IdentitySelected: make(map[identity.NumericIdentity]bool),
	}
}

func (m *ruleMetadata) delete(identity *identity.Identity) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	delete(m.IdentitySelected, identity.ID)
}

func (r *rule) String() string {
	return r.EndpointSelector.String()
}

func (r *rule) getSelector() *api.EndpointSelector {
	if r.NodeSelector.LabelSelector != nil {
		return &r.NodeSelector
	}
	return &r.EndpointSelector
}

func (epd *PerSelectorPolicy) appendL7WildcardRule(ctx *SearchContext) *PerSelectorPolicy {
	// Wildcard rule only needs to be appended if some rules already exist
	switch {
	case len(epd.L7Rules.HTTP) > 0:
		rule := api.PortRuleHTTP{}
		if !rule.Exists(epd.L7Rules) {
			ctx.PolicyTrace("   Merging HTTP wildcard rule: %+v\n", rule)
			epd.L7Rules.HTTP = append(epd.L7Rules.HTTP, rule)
		} else {
			ctx.PolicyTrace("   Merging HTTP wildcard rule, equal rule already exists: %+v\n", rule)
		}
	case len(epd.L7Rules.Kafka) > 0:
		rule := kafka.PortRule{}
		rule.Sanitize()
		if !rule.Exists(epd.L7Rules.Kafka) {
			ctx.PolicyTrace("   Merging Kafka wildcard rule: %+v\n", rule)
			epd.L7Rules.Kafka = append(epd.L7Rules.Kafka, rule)
		} else {
			ctx.PolicyTrace("   Merging Kafka wildcard rule, equal rule already exists: %+v\n", rule)
		}
	case len(epd.L7Rules.DNS) > 0:
		// Wildcarding at L7 for DNS is specified via allowing all via
		// MatchPattern!
		rule := api.PortRuleDNS{MatchPattern: "*"}
		rule.Sanitize()
		if !rule.Exists(epd.L7Rules) {
			ctx.PolicyTrace("   Merging DNS wildcard rule: %+v\n", rule)
			epd.L7Rules.DNS = append(epd.L7Rules.DNS, rule)
		} else {
			ctx.PolicyTrace("   Merging DNS wildcard rule, equal rule already exists: %+v\n", rule)
		}
	case epd.L7Rules.L7Proto != "" && len(epd.L7Rules.L7) > 0:
		rule := api.PortRuleL7{}
		if !rule.Exists(epd.L7Rules) {
			ctx.PolicyTrace("   Merging L7 wildcard rule: %+v\n", rule)
			epd.L7Rules.L7 = append(epd.L7Rules.L7, rule)
		} else {
			ctx.PolicyTrace("   Merging L7 wildcard rule, equal rule already exists: %+v\n", rule)
		}
	}
	return epd
}

func mergePortProto(ctx *SearchContext, existingFilter, filterToMerge *L4Filter, selectorCache *SelectorCache) error {
	// Merge the L7-related data from the filter to merge
	// with the L7-related data already in the existing filter.
	if filterToMerge.L7Parser != ParserTypeNone {
		if existingFilter.L7Parser == ParserTypeNone {
			existingFilter.L7Parser = filterToMerge.L7Parser
		} else if filterToMerge.L7Parser != existingFilter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", filterToMerge.L7Parser, existingFilter.L7Parser)
			return fmt.Errorf("cannot merge conflicting L7 parsers (%s/%s)", filterToMerge.L7Parser, existingFilter.L7Parser)
		}
	}

	for cs, newL7Rules := range filterToMerge.L7RulesPerSelector {
		// 'cs' will be merged or moved (see below), either way it needs
		// to be removed from the map it is in now.
		delete(filterToMerge.L7RulesPerSelector, cs)

		if l7Rules, ok := existingFilter.L7RulesPerSelector[cs]; ok {
			// existing filter already has 'cs', release and merge L7 rules
			selectorCache.RemoveSelector(cs, filterToMerge)

			// skip merging for reserved:none, as it is never
			// selected, and toFQDN rules currently translate to
			// reserved:none as an endpoint selector, causing a
			// merge conflict for different toFQDN destinations
			// with different TLS contexts.
			if cs.IsNone() {
				continue
			}

			if l7Rules.Equal(newL7Rules) {
				continue // identical rules need no merging
			}

			// Merge two non-identical sets of non-nil rules
			if l7Rules != nil && l7Rules.IsDeny {
				// If existing rule is deny then it's a no-op
				// Denies takes priority over any rule.
				continue
			} else if newL7Rules != nil && newL7Rules.IsDeny {
				// Overwrite existing filter if the new rule is a deny case
				// Denies takes priority over any rule.
				existingFilter.L7RulesPerSelector[cs] = newL7Rules
				continue
			}

			// nil L7 rules wildcard L7. When merging with a non-nil rule, the nil must be expanded
			// to an actual wildcard rule for the specific L7
			if l7Rules.IsEmpty() && !newL7Rules.IsEmpty() {
				existingFilter.L7RulesPerSelector[cs] = newL7Rules.appendL7WildcardRule(ctx)
				continue
			}
			if !l7Rules.IsEmpty() && newL7Rules.IsEmpty() {
				existingFilter.L7RulesPerSelector[cs] = l7Rules.appendL7WildcardRule(ctx)
				continue
			}

			if !newL7Rules.TerminatingTLS.Equal(l7Rules.TerminatingTLS) {
				ctx.PolicyTrace("   Merge conflict: mismatching terminating TLS contexts %v/%v\n", newL7Rules.TerminatingTLS, l7Rules.TerminatingTLS)
				return fmt.Errorf("cannot merge conflicting terminating TLS contexts for cached selector %s: (%v/%v)", cs.String(), newL7Rules.TerminatingTLS, l7Rules.TerminatingTLS)
			}
			if !newL7Rules.OriginatingTLS.Equal(l7Rules.OriginatingTLS) {
				ctx.PolicyTrace("   Merge conflict: mismatching originating TLS contexts %v/%v\n", newL7Rules.OriginatingTLS, l7Rules.OriginatingTLS)
				return fmt.Errorf("cannot merge conflicting originating TLS contexts for cached selector %s: (%v/%v)", cs.String(), newL7Rules.OriginatingTLS, l7Rules.OriginatingTLS)
			}

			switch {
			case len(newL7Rules.HTTP) > 0:
				if len(l7Rules.Kafka) > 0 || len(l7Rules.DNS) > 0 || l7Rules.L7Proto != "" {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.HTTP {
					if !newRule.Exists(l7Rules.L7Rules) {
						l7Rules.HTTP = append(l7Rules.HTTP, newRule)
					}
				}
			case len(newL7Rules.Kafka) > 0:
				if len(l7Rules.HTTP) > 0 || len(l7Rules.DNS) > 0 || l7Rules.L7Proto != "" {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.Kafka {
					if !newRule.Exists(l7Rules.L7Rules.Kafka) {
						l7Rules.Kafka = append(l7Rules.Kafka, newRule)
					}
				}
			case newL7Rules.L7Proto != "":
				if len(l7Rules.Kafka) > 0 || len(l7Rules.HTTP) > 0 || len(l7Rules.DNS) > 0 || (l7Rules.L7Proto != "" && l7Rules.L7Proto != newL7Rules.L7Proto) {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("cannot merge conflicting L7 rule types")
				}
				if l7Rules.L7Proto == "" {
					l7Rules.L7Proto = newL7Rules.L7Proto
				}

				for _, newRule := range newL7Rules.L7 {
					if !newRule.Exists(l7Rules.L7Rules) {
						l7Rules.L7 = append(l7Rules.L7, newRule)
					}
				}
			case len(newL7Rules.DNS) > 0:
				if len(l7Rules.HTTP) > 0 || len(l7Rules.Kafka) > 0 || len(l7Rules.L7) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.DNS {
					if !newRule.Exists(l7Rules.L7Rules) {
						l7Rules.DNS = append(l7Rules.DNS, newRule)
					}
				}

			default:
				ctx.PolicyTrace("   No L7 rules to merge.\n")
			}
			existingFilter.L7RulesPerSelector[cs] = l7Rules
		} else { // 'cs' is not in the existing filter yet
			// Update selector owner to the existing filter
			selectorCache.ChangeUser(cs, filterToMerge, existingFilter)

			// Move L7 rules over.
			existingFilter.L7RulesPerSelector[cs] = newL7Rules

			if cs.IsWildcard() {
				existingFilter.wildcard = cs
			}
		}
	}

	return nil
}

// mergeIngressPortProto merges all rules which share the same port & protocol that
// select a given set of endpoints. It updates the L4Filter mapped to by the specified
// port and protocol with the contents of the provided PortRule. If the rule
// being merged has conflicting L7 rules with those already in the provided
// L4PolicyMap for the specified port-protocol tuple, it returns an error.
//
// If any rules contain L7 rules that select Host or Remote Node and we should
// accept all traffic from host, the L7 rules will be translated into L7
// wildcards via 'hostWildcardL7'. That is to say, traffic will be
// forwarded to the proxy for endpoints matching those labels, but the proxy
// will allow all such traffic.
func mergeIngressPortProto(policyCtx PolicyContext, ctx *SearchContext, endpoints api.EndpointSelectorSlice, hostWildcardL7 []string,
	r api.Ports, p api.PortProtocol, proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	// Create a new L4Filter
	filterToMerge, err := createL4IngressFilter(policyCtx, endpoints, hostWildcardL7, r, p, proto, ruleLabels)
	if err != nil {
		return 0, err
	}

	err = addL4Filter(policyCtx, ctx, resMap, p, proto, filterToMerge, ruleLabels)
	if err != nil {
		return 0, err
	}
	return 1, err
}

func traceL3(ctx *SearchContext, peerEndpoints api.EndpointSelectorSlice, direction string, isDeny bool) {
	var result strings.Builder

	// Requirements will be cloned into every selector, only trace them once.
	if len(peerEndpoints[0].MatchExpressions) > 0 {
		sel := peerEndpoints[0]
		result.WriteString("    Enforcing requirements ")
		result.WriteString(fmt.Sprintf("%+v", sel.MatchExpressions))
		result.WriteString("\n")
	}
	// EndpointSelector
	for _, sel := range peerEndpoints {
		if len(sel.MatchLabels) > 0 {
			if !isDeny {
				result.WriteString("    Allows ")
			} else {
				result.WriteString("    Denies ")
			}
			result.WriteString(direction)
			result.WriteString(" labels ")
			result.WriteString(sel.String())
			result.WriteString("\n")
		}
	}
	ctx.PolicyTrace(result.String())
}

// portRulesCoverContext determines whether L4 portions of rules cover the
// specified port models.
//
// Returns true if the list of ports is 0, or the rules match the ports.
func rulePortsCoverSearchContext(ports []api.PortProtocol, ctx *SearchContext) bool {
	if len(ctx.DPorts) == 0 {
		return true
	}
	for _, p := range ports {
		for _, dp := range ctx.DPorts {
			tracePort := api.PortProtocol{
				Protocol: api.L4Proto(dp.Protocol),
			}
			if dp.Name != "" {
				tracePort.Port = dp.Name
			} else {
				tracePort.Port = fmt.Sprintf("%d", dp.Port)
			}
			if p.Covers(tracePort) {
				return true
			}
		}
	}
	return false
}

func mergeIngress(policyCtx PolicyContext, ctx *SearchContext, fromEndpoints api.EndpointSelectorSlice, toPorts, icmp api.PortsIterator, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	found := 0

	if ctx.From != nil && len(fromEndpoints) > 0 {
		if ctx.TraceEnabled() {
			traceL3(ctx, fromEndpoints, "from", policyCtx.IsDeny())
		}
		if !fromEndpoints.Matches(ctx.From) {
			ctx.PolicyTrace("      No label match for %s", ctx.From)
			return 0, nil
		}
		ctx.PolicyTrace("      Found all required labels")
	}

	// Daemon options may induce L3 allows for host/world. In this case, if
	// we find any L7 rules matching host/world then we need to turn any L7
	// restrictions on these endpoints into L7 allow-all so that the
	// traffic is always allowed, but is also always redirected through the
	// proxy
	hostWildcardL7 := make([]string, 0, 2)
	if option.Config.AlwaysAllowLocalhost() {
		hostWildcardL7 = append(hostWildcardL7, labels.IDNameHost)
		if !option.Config.EnableRemoteNodeIdentity {
			hostWildcardL7 = append(hostWildcardL7, labels.IDNameRemoteNode)
		}
	}

	var (
		cnt int
		err error
	)

	// L3-only rule (with requirements folded into fromEndpoints).
	if toPorts.Len() == 0 && icmp.Len() == 0 && len(fromEndpoints) > 0 {
		cnt, err = mergeIngressPortProto(policyCtx, ctx, fromEndpoints, hostWildcardL7, &api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap)
		if err != nil {
			return found, err
		}
	}

	found += cnt

	err = toPorts.Iterate(func(r api.Ports) error {
		// For L4 Policy, an empty slice of EndpointSelector indicates that the
		// rule allows all at L3 - explicitly specify this by creating a slice
		// with the WildcardEndpointSelector.
		if len(fromEndpoints) == 0 {
			fromEndpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		}
		if !policyCtx.IsDeny() {
			ctx.PolicyTrace("      Allows port %v\n", r.GetPortProtocols())
		} else {
			ctx.PolicyTrace("      Denies port %v\n", r.GetPortProtocols())
		}
		if !rulePortsCoverSearchContext(r.GetPortProtocols(), ctx) {
			ctx.PolicyTrace("        No port match found\n")
			return nil
		}
		pr := r.GetPortRule()
		if pr != nil {
			if pr.Rules != nil && pr.Rules.L7Proto != "" {
				ctx.PolicyTrace("        l7proto: \"%s\"\n", pr.Rules.L7Proto)
			}
			if !pr.Rules.IsEmpty() {
				for _, l7 := range pr.Rules.HTTP {
					ctx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.Kafka {
					ctx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.L7 {
					ctx.PolicyTrace("          %+v\n", l7)
				}
			}
		}

		for _, p := range r.GetPortProtocols() {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeIngressPortProto(policyCtx, ctx, fromEndpoints, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			} else {
				cnt, err := mergeIngressPortProto(policyCtx, ctx, fromEndpoints, hostWildcardL7, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeIngressPortProto(policyCtx, ctx, fromEndpoints, hostWildcardL7, r, p, api.ProtoUDP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			}
		}
		return nil
	})
	if err != nil {
		return found, err
	}

	err = icmp.Iterate(func(r api.Ports) error {
		if len(fromEndpoints) == 0 {
			fromEndpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		}
		if !policyCtx.IsDeny() {
			ctx.PolicyTrace("      Allows ICMP type %v\n", r.GetPortProtocols())
		} else {
			ctx.PolicyTrace("      Denies ICMP type %v\n", r.GetPortProtocols())
		}
		if !rulePortsCoverSearchContext(r.GetPortProtocols(), ctx) {
			ctx.PolicyTrace("        No ICMP type match found\n")
			return nil
		}

		for _, p := range r.GetPortProtocols() {
			cnt, err := mergeIngressPortProto(policyCtx, ctx, fromEndpoints, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap)
			if err != nil {
				return err
			}
			found += cnt
		}
		return nil
	})

	return found, err
}

func (state *traceState) selectRule(ctx *SearchContext, r *rule) {
	ctx.PolicyTrace("* Rule %s: selected\n", r)
	state.selectedRules++
}

func (state *traceState) unSelectRule(ctx *SearchContext, labels labels.LabelArray, r *rule) {
	ctx.PolicyTraceVerbose("  Rule %s: did not select %+v\n", r, labels)
}

// resolveIngressPolicy analyzes the rule against the given SearchContext, and
// merges it with any prior-generated policy within the provided L4Policy.
// Requirements based off of all Ingress requirements (set in FromRequires) in
// other rules are stored in the specified slice of LabelSelectorRequirement.
// These requirements are dynamically inserted into a copy of the receiver rule,
// as requirements form conjunctions across all rules.
func (r *rule) resolveIngressPolicy(
	policyCtx PolicyContext,
	ctx *SearchContext,
	state *traceState,
	result L4PolicyMap,
	requirements, requirementsDeny []slim_metav1.LabelSelectorRequirement,
) (
	L4PolicyMap, error,
) {
	if !ctx.rulesSelect {
		if !r.getSelector().Matches(ctx.To) {
			state.unSelectRule(ctx, ctx.To, r)
			return nil, nil
		}
	}

	state.selectRule(ctx, r)
	found, foundDeny := 0, 0

	if len(r.Ingress) == 0 && len(r.IngressDeny) == 0 {
		ctx.PolicyTrace("    No ingress rules\n")
	}
	for _, ingressRule := range r.Ingress {
		fromEndpoints := ingressRule.GetSourceEndpointSelectorsWithRequirements(requirements)
		cnt, err := mergeIngress(policyCtx, ctx, fromEndpoints, ingressRule.ToPorts, ingressRule.ICMPs, r.Rule.Labels.DeepCopy(), result)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			found += cnt
		}
	}

	oldDeny := policyCtx.SetDeny(true)
	defer func() {
		policyCtx.SetDeny(oldDeny)
	}()
	for _, ingressRule := range r.IngressDeny {
		fromEndpoints := ingressRule.GetSourceEndpointSelectorsWithRequirements(requirementsDeny)
		cnt, err := mergeIngress(policyCtx, ctx, fromEndpoints, ingressRule.ToPorts, ingressRule.ICMPs, r.Rule.Labels.DeepCopy(), result)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			foundDeny += cnt
		}
	}

	if found+foundDeny > 0 {
		if found != 0 {
			state.matchedRules++
		}
		if foundDeny != 0 {
			state.matchedDenyRules++
		}
		return result, nil
	}

	return nil, nil
}

func (r *rule) matches(securityIdentity *identity.Identity) bool {
	r.metadata.Mutex.Lock()
	defer r.metadata.Mutex.Unlock()
	var ruleMatches bool

	if ruleMatches, cached := r.metadata.IdentitySelected[securityIdentity.ID]; cached {
		return ruleMatches
	}
	isNode := securityIdentity.ID == identity.ReservedIdentityHost
	if (r.NodeSelector.LabelSelector != nil) != isNode {
		r.metadata.IdentitySelected[securityIdentity.ID] = false
		return ruleMatches
	}
	// Fall back to costly matching.
	if ruleMatches = r.getSelector().Matches(securityIdentity.LabelArray); ruleMatches {
		// Update cache so we don't have to do costly matching again.
		r.metadata.IdentitySelected[securityIdentity.ID] = true
	} else {
		r.metadata.IdentitySelected[securityIdentity.ID] = false
	}

	return ruleMatches
}

// ****************** EGRESS POLICY ******************

func mergeEgress(policyCtx PolicyContext, ctx *SearchContext, toEndpoints api.EndpointSelectorSlice, toPorts, icmp api.PortsIterator, ruleLabels labels.LabelArray, resMap L4PolicyMap, fqdns api.FQDNSelectorSlice) (int, error) {
	found := 0

	if ctx.To != nil && len(toEndpoints) > 0 {
		if ctx.TraceEnabled() {
			traceL3(ctx, toEndpoints, "to", policyCtx.IsDeny())
		}
		if !toEndpoints.Matches(ctx.To) {
			ctx.PolicyTrace("      No label match for %s", ctx.To)
			return 0, nil
		}
		ctx.PolicyTrace("      Found all required labels")
	}

	var (
		cnt int
		err error
	)

	// L3-only rule (with requirements folded into toEndpoints).
	if toPorts.Len() == 0 && icmp.Len() == 0 && len(toEndpoints) > 0 {
		cnt, err = mergeEgressPortProto(policyCtx, ctx, toEndpoints, &api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap, fqdns)
		if err != nil {
			return found, err
		}
	}

	found += cnt

	err = toPorts.Iterate(func(r api.Ports) error {
		// For L4 Policy, an empty slice of EndpointSelector indicates that the
		// rule allows all at L3 - explicitly specify this by creating a slice
		// with the WildcardEndpointSelector.
		if len(toEndpoints) == 0 {
			toEndpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		}
		if !policyCtx.IsDeny() {
			ctx.PolicyTrace("      Allows port %v\n", r.GetPortProtocols())
		} else {
			ctx.PolicyTrace("      Denies port %v\n", r.GetPortProtocols())
		}

		pr := r.GetPortRule()
		if pr != nil {
			if !pr.Rules.IsEmpty() {
				for _, l7 := range pr.Rules.HTTP {
					ctx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.Kafka {
					ctx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.L7 {
					ctx.PolicyTrace("          %+v\n", l7)
				}
			}
		}

		for _, p := range r.GetPortProtocols() {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeEgressPortProto(policyCtx, ctx, toEndpoints, r, p, p.Protocol, ruleLabels, resMap, fqdns)
				if err != nil {
					return err
				}
				found += cnt
			} else {
				cnt, err := mergeEgressPortProto(policyCtx, ctx, toEndpoints, r, p, api.ProtoTCP, ruleLabels, resMap, fqdns)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeEgressPortProto(policyCtx, ctx, toEndpoints, r, p, api.ProtoUDP, ruleLabels, resMap, fqdns)
				if err != nil {
					return err
				}
				found += cnt
			}
		}
		return nil
	},
	)
	if err != nil {
		return found, err
	}

	err = icmp.Iterate(func(r api.Ports) error {
		if len(toEndpoints) == 0 {
			toEndpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		}
		if !policyCtx.IsDeny() {
			ctx.PolicyTrace("      Allows ICMP type %v\n", r.GetPortProtocols())
		} else {
			ctx.PolicyTrace("      Denies ICMP type %v\n", r.GetPortProtocols())
		}

		for _, p := range r.GetPortProtocols() {
			cnt, err := mergeEgressPortProto(policyCtx, ctx, toEndpoints, r, p, p.Protocol, ruleLabels, resMap, fqdns)
			if err != nil {
				return err
			}
			found += cnt
		}
		return nil
	})

	return found, err
}

// mergeEgressPortProto merges all rules which share the same port & protocol that
// select a given set of endpoints. It updates the L4Filter mapped to by the specified
// port and protocol with the contents of the provided PortRule. If the rule
// being merged has conflicting L7 rules with those already in the provided
// L4PolicyMap for the specified port-protocol tuple, it returns an error.
func mergeEgressPortProto(policyCtx PolicyContext, ctx *SearchContext, endpoints api.EndpointSelectorSlice, r api.Ports, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap, fqdns api.FQDNSelectorSlice) (int, error) {
	// Create a new L4Filter
	filterToMerge, err := createL4EgressFilter(policyCtx, endpoints, r, p, proto, ruleLabels, fqdns)
	if err != nil {
		return 0, err
	}

	err = addL4Filter(policyCtx, ctx, resMap, p, proto, filterToMerge, ruleLabels)
	if err != nil {
		return 0, err
	}
	return 1, err
}

func (r *rule) resolveEgressPolicy(
	policyCtx PolicyContext,
	ctx *SearchContext,
	state *traceState,
	result L4PolicyMap,
	requirements, requirementsDeny []slim_metav1.LabelSelectorRequirement,
) (
	L4PolicyMap, error,
) {
	if !ctx.rulesSelect {
		if !r.getSelector().Matches(ctx.From) {
			state.unSelectRule(ctx, ctx.From, r)
			return nil, nil
		}
	}

	state.selectRule(ctx, r)
	found, foundDeny := 0, 0

	if len(r.Egress) == 0 && len(r.EgressDeny) == 0 {
		ctx.PolicyTrace("    No egress rules\n")
	}
	for _, egressRule := range r.Egress {
		toEndpoints := egressRule.GetDestinationEndpointSelectorsWithRequirements(requirements)
		cnt, err := mergeEgress(policyCtx, ctx, toEndpoints, egressRule.ToPorts, egressRule.ICMPs, r.Rule.Labels.DeepCopy(), result, egressRule.ToFQDNs)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			found += cnt
		}
	}

	oldDeny := policyCtx.SetDeny(true)
	defer func() {
		policyCtx.SetDeny(oldDeny)
	}()
	for _, egressRule := range r.EgressDeny {
		toEndpoints := egressRule.GetDestinationEndpointSelectorsWithRequirements(requirementsDeny)
		cnt, err := mergeEgress(policyCtx, ctx, toEndpoints, egressRule.ToPorts, egressRule.ICMPs, r.Rule.Labels.DeepCopy(), result, nil)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			foundDeny += cnt
		}
	}

	if found+foundDeny > 0 {
		if found != 0 {
			state.matchedRules++
		}
		if foundDeny != 0 {
			state.matchedDenyRules++
		}
		return result, nil
	}

	return nil, nil
}
