// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/proxy/pkg/policy/api/kafka"

	"github.com/cilium/cilium/pkg/identity"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

type rule struct {
	api.Rule

	metadata *ruleMetadata
}

type ruleMetadata struct {
	// mutex protects all fields in this type.
	Mutex lock.Mutex

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

func (epd *PerSelectorPolicy) appendL7WildcardRule(ctx *SearchContext) api.L7Rules {
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
	return epd.L7Rules
}

// takesListenerPrecedenceOver returns true if the listener reference in 'l7Rules' takes precedence
// over the listener reference in 'other'.
func (l7Rules *PerSelectorPolicy) takesListenerPrecedenceOver(other *PerSelectorPolicy) bool {
	var priority, otherPriority uint16

	// decrement by one to wrap the undefined value (0) to be the highest numerical
	// value of the uint16, which is the lowest possible priority
	priority = l7Rules.Priority - 1
	otherPriority = other.Priority - 1

	return priority < otherPriority
}

// mergeListenerReference merges listener reference from 'newL7Rules' to 'l7Rules', giving
// precedence to listener with the lowest priority, if any.
func (l7Rules *PerSelectorPolicy) mergeListenerReference(newL7Rules *PerSelectorPolicy) error {
	// Nothing to do if 'newL7Rules' has no listener reference
	if newL7Rules.Listener == "" {
		return nil
	}

	// Nothing to do if the listeners are already the same and have the same priority
	if newL7Rules.Listener == l7Rules.Listener && l7Rules.Priority == newL7Rules.Priority {
		return nil
	}

	// Nothing to do if 'l7Rules' takes precedence
	if l7Rules.takesListenerPrecedenceOver(newL7Rules) {
		return nil
	}

	// override if 'l7Rules' has no listener or 'newL7Rules' takes precedence
	if l7Rules.Listener == "" || newL7Rules.takesListenerPrecedenceOver(l7Rules) {
		l7Rules.Listener = newL7Rules.Listener
		l7Rules.Priority = newL7Rules.Priority
		return nil
	}

	// otherwise error on conflict
	return fmt.Errorf("cannot merge conflicting CiliumEnvoyConfig Listeners (%v/%v) with the same priority (%d)", newL7Rules.Listener, l7Rules.Listener, l7Rules.Priority)
}

func mergePortProto(ctx *SearchContext, existingFilter, filterToMerge *L4Filter, selectorCache *SelectorCache) (err error) {
	// Merge the L7-related data from the filter to merge
	// with the L7-related data already in the existing filter.
	existingFilter.L7Parser, err = existingFilter.L7Parser.Merge(filterToMerge.L7Parser)
	if err != nil {
		ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", filterToMerge.L7Parser, existingFilter.L7Parser)
		return err
	}

	for cs, newL7Rules := range filterToMerge.PerSelectorPolicies {
		// 'cs' will be merged or moved (see below), either way it needs
		// to be removed from the map it is in now.
		delete(filterToMerge.PerSelectorPolicies, cs)

		if l7Rules, ok := existingFilter.PerSelectorPolicies[cs]; ok {
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
				existingFilter.PerSelectorPolicies[cs] = newL7Rules
				continue
			}

			// One of the rules may be a nil rule, expand it to an empty non-nil rule
			if l7Rules == nil {
				l7Rules = &PerSelectorPolicy{}
			}
			if newL7Rules == nil {
				newL7Rules = &PerSelectorPolicy{}
			}

			// Merge isRedirect flag
			l7Rules.isRedirect = l7Rules.isRedirect || newL7Rules.isRedirect

			// Merge listener reference
			if err := l7Rules.mergeListenerReference(newL7Rules); err != nil {
				ctx.PolicyTrace("   Merge conflict: %s\n", err.Error())
				return err
			}

			if l7Rules.Authentication == nil || newL7Rules.Authentication == nil {
				if newL7Rules.Authentication != nil {
					l7Rules.Authentication = newL7Rules.Authentication
				}
			} else if !newL7Rules.Authentication.DeepEqual(l7Rules.Authentication) {
				ctx.PolicyTrace("   Merge conflict: mismatching auth types %s/%s\n", newL7Rules.Authentication.Mode, l7Rules.Authentication.Mode)
				return fmt.Errorf("cannot merge conflicting authentication types (%s/%s)", newL7Rules.Authentication.Mode, l7Rules.Authentication.Mode)
			}

			if l7Rules.TerminatingTLS == nil || newL7Rules.TerminatingTLS == nil {
				if newL7Rules.TerminatingTLS != nil {
					l7Rules.TerminatingTLS = newL7Rules.TerminatingTLS
				}
			} else if !newL7Rules.TerminatingTLS.Equal(l7Rules.TerminatingTLS) {
				ctx.PolicyTrace("   Merge conflict: mismatching terminating TLS contexts %v/%v\n", newL7Rules.TerminatingTLS, l7Rules.TerminatingTLS)
				return fmt.Errorf("cannot merge conflicting terminating TLS contexts for cached selector %s: (%v/%v)", cs.String(), newL7Rules.TerminatingTLS, l7Rules.TerminatingTLS)
			}
			if l7Rules.OriginatingTLS == nil || newL7Rules.OriginatingTLS == nil {
				if newL7Rules.OriginatingTLS != nil {
					l7Rules.OriginatingTLS = newL7Rules.OriginatingTLS
				}
			} else if !newL7Rules.OriginatingTLS.Equal(l7Rules.OriginatingTLS) {
				ctx.PolicyTrace("   Merge conflict: mismatching originating TLS contexts %v/%v\n", newL7Rules.OriginatingTLS, l7Rules.OriginatingTLS)
				return fmt.Errorf("cannot merge conflicting originating TLS contexts for cached selector %s: (%v/%v)", cs.String(), newL7Rules.OriginatingTLS, l7Rules.OriginatingTLS)
			}

			// For now we simply merge the set of allowed SNIs from different rules
			// to/from the *same remote*, port, and protocol. This means that if any
			// rule requires SNI, then all traffic to that remote/port requires TLS,
			// even if other merged rules would be fine without TLS. Any SNI from all
			// applicable rules is allowed.
			//
			// Preferably we could allow different rules for each SNI, but for now the
			// combination of all L7 rules is allowed for all the SNIs. For example, if
			// SNI and TLS termination are used together so that L7 filtering is
			// possible, in this example:
			//
			// - existing: SNI: public.example.com
			// - new:      SNI: private.example.com HTTP: path="/public"
			//
			// Separately, these rule allow access to all paths at SNI
			// public.example.com and path private.example.com/public, but currently we
			// allow all paths also at private.example.com. This may be clamped down if
			// there is sufficient demand for SNI and TLS termination together.
			//
			// Note however that SNI rules are typically used with `toFQDNs`, each of
			// which defines a separate destination, so that SNIs for different
			// `toFQDNs` will not be merged together.
			l7Rules.ServerNames = l7Rules.ServerNames.Merge(newL7Rules.ServerNames)

			// L7 rules can be applied with SNI filtering only if the TLS is also
			// terminated
			if len(l7Rules.ServerNames) > 0 && !l7Rules.L7Rules.IsEmpty() && l7Rules.TerminatingTLS == nil {
				ctx.PolicyTrace("   Merge conflict: cannot use SNI filtering with L7 rules without TLS termination: %v\n", l7Rules.ServerNames)
				return fmt.Errorf("cannot merge L7 rules for cached selector %s with SNI filtering without TLS termination: %v", cs.String(), l7Rules.ServerNames)
			}

			// empty L7 rules effectively wildcard L7. When merging with a non-empty
			// rule, the empty must be expanded to an actual wildcard rule for the
			// specific L7
			if !l7Rules.HasL7Rules() && newL7Rules.HasL7Rules() {
				l7Rules.L7Rules = newL7Rules.appendL7WildcardRule(ctx)
				existingFilter.PerSelectorPolicies[cs] = l7Rules
				continue
			}
			if l7Rules.HasL7Rules() && !newL7Rules.HasL7Rules() {
				l7Rules.appendL7WildcardRule(ctx)
				existingFilter.PerSelectorPolicies[cs] = l7Rules
				continue
			}

			// We already know from the L7Parser.Merge() above that there are no
			// conflicting parser types, and rule validation only allows one type of L7
			// rules in a rule, so we can just merge the rules here.
			for _, newRule := range newL7Rules.HTTP {
				if !newRule.Exists(l7Rules.L7Rules) {
					l7Rules.HTTP = append(l7Rules.HTTP, newRule)
				}
			}
			for _, newRule := range newL7Rules.Kafka {
				if !newRule.Exists(l7Rules.L7Rules.Kafka) {
					l7Rules.Kafka = append(l7Rules.Kafka, newRule)
				}
			}
			if l7Rules.L7Proto == "" && newL7Rules.L7Proto != "" {
				l7Rules.L7Proto = newL7Rules.L7Proto
			}
			for _, newRule := range newL7Rules.L7 {
				if !newRule.Exists(l7Rules.L7Rules) {
					l7Rules.L7 = append(l7Rules.L7, newRule)
				}
			}
			for _, newRule := range newL7Rules.DNS {
				if !newRule.Exists(l7Rules.L7Rules) {
					l7Rules.DNS = append(l7Rules.DNS, newRule)
				}
			}
			// Update the pointer in the map in case it was newly allocated
			existingFilter.PerSelectorPolicies[cs] = l7Rules
		} else { // 'cs' is not in the existing filter yet
			// Update selector owner to the existing filter
			selectorCache.ChangeUser(cs, filterToMerge, existingFilter)

			// Move L7 rules over.
			existingFilter.PerSelectorPolicies[cs] = newL7Rules

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
func mergeIngressPortProto(policyCtx PolicyContext, ctx *SearchContext, endpoints api.EndpointSelectorSlice, auth *api.Authentication, hostWildcardL7 []string,
	r api.Ports, p api.PortProtocol, proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	// Create a new L4Filter
	filterToMerge, err := createL4IngressFilter(policyCtx, endpoints, auth, hostWildcardL7, r, p, proto, ruleLabels)
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
				tracePort.Port = strconv.FormatUint(uint64(dp.Port), 10)
			}
			if p.Covers(tracePort) {
				return true
			}
		}
	}
	return false
}

func mergeIngress(policyCtx PolicyContext, ctx *SearchContext, fromEndpoints api.EndpointSelectorSlice, auth *api.Authentication, toPorts, icmp api.PortsIterator, ruleLabels labels.LabelArray, resMap L4PolicyMap) (int, error) {
	found := 0

	// short-circuit if no endpoint is selected
	if fromEndpoints == nil {
		return found, nil
	}

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
	}

	var (
		cnt int
		err error
	)

	// L3-only rule (with requirements folded into fromEndpoints).
	if toPorts.Len() == 0 && icmp.Len() == 0 && len(fromEndpoints) > 0 {
		cnt, err = mergeIngressPortProto(policyCtx, ctx, fromEndpoints, auth, hostWildcardL7, &api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap)
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
			if p.Protocol.IsAny() {
				cnt, err := mergeIngressPortProto(policyCtx, ctx, fromEndpoints, auth, hostWildcardL7, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeIngressPortProto(policyCtx, ctx, fromEndpoints, auth, hostWildcardL7, r, p, api.ProtoUDP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeIngressPortProto(policyCtx, ctx, fromEndpoints, auth, hostWildcardL7, r, p, api.ProtoSCTP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			} else {
				cnt, err := mergeIngressPortProto(policyCtx, ctx, fromEndpoints, auth, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap)
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
			cnt, err := mergeIngressPortProto(policyCtx, ctx, fromEndpoints, auth, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap)
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
		cnt, err := mergeIngress(policyCtx, ctx, fromEndpoints, ingressRule.Authentication, ingressRule.ToPorts, ingressRule.ICMPs, r.Rule.Labels.DeepCopy(), result)
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
		cnt, err := mergeIngress(policyCtx, ctx, fromEndpoints, nil, ingressRule.ToPorts, ingressRule.ICMPs, r.Rule.Labels.DeepCopy(), result)
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
	isNode := securityIdentity.ID == identity.ReservedIdentityHost

	if ruleMatches, cached := r.metadata.IdentitySelected[securityIdentity.ID]; cached {
		return ruleMatches
	}

	// Short-circuit if the rule's selector type (node vs. endpoint) does not match the
	// identity's type
	if (r.NodeSelector.LabelSelector != nil) != isNode {
		r.metadata.IdentitySelected[securityIdentity.ID] = false
		return false
	}

	// Fall back to costly matching.
	ruleMatches := r.getSelector().Matches(securityIdentity.LabelArray)

	// Update cache so we don't have to do costly matching again.
	// the local Host identity has mutable labels, so we cannot use the cache
	if !isNode {
		r.metadata.IdentitySelected[securityIdentity.ID] = ruleMatches
	}

	return ruleMatches
}

// ****************** EGRESS POLICY ******************

func mergeEgress(policyCtx PolicyContext, ctx *SearchContext, toEndpoints api.EndpointSelectorSlice, auth *api.Authentication, toPorts, icmp api.PortsIterator, ruleLabels labels.LabelArray, resMap L4PolicyMap, fqdns api.FQDNSelectorSlice) (int, error) {
	found := 0

	// short-circuit if no endpoint is selected
	if toEndpoints == nil {
		return found, nil
	}

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
		cnt, err = mergeEgressPortProto(policyCtx, ctx, toEndpoints, auth, &api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap, fqdns)
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
			if p.Protocol.IsAny() {
				cnt, err := mergeEgressPortProto(policyCtx, ctx, toEndpoints, auth, r, p, api.ProtoTCP, ruleLabels, resMap, fqdns)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeEgressPortProto(policyCtx, ctx, toEndpoints, auth, r, p, api.ProtoUDP, ruleLabels, resMap, fqdns)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeEgressPortProto(policyCtx, ctx, toEndpoints, auth, r, p, api.ProtoSCTP, ruleLabels, resMap, fqdns)
				if err != nil {
					return err
				}
				found += cnt
			} else {
				cnt, err := mergeEgressPortProto(policyCtx, ctx, toEndpoints, auth, r, p, p.Protocol, ruleLabels, resMap, fqdns)
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
			cnt, err := mergeEgressPortProto(policyCtx, ctx, toEndpoints, auth, r, p, p.Protocol, ruleLabels, resMap, fqdns)
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
func mergeEgressPortProto(policyCtx PolicyContext, ctx *SearchContext, endpoints api.EndpointSelectorSlice, auth *api.Authentication, r api.Ports, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap, fqdns api.FQDNSelectorSlice) (int, error) {
	// Create a new L4Filter
	filterToMerge, err := createL4EgressFilter(policyCtx, endpoints, auth, r, p, proto, ruleLabels, fqdns)
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
		cnt, err := mergeEgress(policyCtx, ctx, toEndpoints, egressRule.Authentication, egressRule.ToPorts, egressRule.ICMPs, r.Rule.Labels.DeepCopy(), result, egressRule.ToFQDNs)
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
		cnt, err := mergeEgress(policyCtx, ctx, toEndpoints, nil, egressRule.ToPorts, egressRule.ICMPs, r.Rule.Labels.DeepCopy(), result, nil)
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
