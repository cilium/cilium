// Copyright 2016-2019 Authors of Cilium
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
	"bytes"
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
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
	return fmt.Sprintf("%v", r.EndpointSelector)
}

func (l4 *L4Filter) mergeCachedSelectors(from *L4Filter, selectorCache *SelectorCache) {
	for _, cs := range from.CachedSelectors {
		if l4.CachedSelectors.Insert(cs) {
			// Update selector owner to the existingFilter
			selectorCache.ChangeUser(cs, from, l4)
		} else {
			// selector was already in existingFilter.CachedSelectors, release
			selectorCache.RemoveSelector(cs, from)
		}
	}
	from.CachedSelectors = nil
}

func mergePortProto(ctx *SearchContext, existingFilter, filterToMerge *L4Filter, selectorCache *SelectorCache) error {
	// Handle cases where filter we are merging new rule with, new rule itself
	// allows all traffic on L3, or both rules allow all traffic on L3.
	if existingFilter.AllowsAllAtL3() {
		// Case 1: existing filter selects all endpoints, which means that this filter
		// can now simply select all endpoints.
		//
		// Release references held by filterToMerge.CachedSelectors
		selectorCache.RemoveSelectors(filterToMerge.CachedSelectors, filterToMerge)
		filterToMerge.CachedSelectors = nil
	} else {
		// Case 2: Merge selectors from filterToMerge to the existingFilter.
		if filterToMerge.AllowsAllAtL3() {
			// Allowing all, release selectors from existingFilter
			selectorCache.RemoveSelectors(existingFilter.CachedSelectors, existingFilter)
			existingFilter.CachedSelectors = nil
			existingFilter.allowsAllAtL3 = true
		}
		existingFilter.mergeCachedSelectors(filterToMerge, selectorCache)
	}

	// Merge the L7-related data from the arguments provided to this function
	// with the existing L7-related data already in the filter.
	if filterToMerge.L7Parser != ParserTypeNone {
		if existingFilter.L7Parser == ParserTypeNone {
			existingFilter.L7Parser = filterToMerge.L7Parser
		} else if filterToMerge.L7Parser != existingFilter.L7Parser {
			ctx.PolicyTrace("   Merge conflict: mismatching parsers %s/%s\n", filterToMerge.L7Parser, existingFilter.L7Parser)
			return fmt.Errorf("Cannot merge conflicting L7 parsers (%s/%s)", filterToMerge.L7Parser, existingFilter.L7Parser)
		}
	}

	for cs, newL7Rules := range filterToMerge.L7RulesPerEp {
		if l7Rules, ok := existingFilter.L7RulesPerEp[cs]; ok {
			switch {
			case len(newL7Rules.HTTP) > 0:
				if len(l7Rules.Kafka) > 0 || len(l7Rules.DNS) > 0 || l7Rules.L7Proto != "" {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.HTTP {
					if !newRule.Exists(l7Rules) {
						l7Rules.HTTP = append(l7Rules.HTTP, newRule)
					}
				}
			case len(newL7Rules.Kafka) > 0:
				if len(l7Rules.HTTP) > 0 || len(l7Rules.DNS) > 0 || l7Rules.L7Proto != "" {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.Kafka {
					if !newRule.Exists(l7Rules) {
						l7Rules.Kafka = append(l7Rules.Kafka, newRule)
					}
				}
			case newL7Rules.L7Proto != "":
				if len(l7Rules.Kafka) > 0 || len(l7Rules.HTTP) > 0 || len(l7Rules.DNS) > 0 || (l7Rules.L7Proto != "" && l7Rules.L7Proto != newL7Rules.L7Proto) {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}
				if l7Rules.L7Proto == "" {
					l7Rules.L7Proto = newL7Rules.L7Proto
				}

				for _, newRule := range newL7Rules.L7 {
					if !newRule.Exists(l7Rules) {
						l7Rules.L7 = append(l7Rules.L7, newRule)
					}
				}
			case len(newL7Rules.DNS) > 0:
				if len(l7Rules.HTTP) > 0 || len(l7Rules.Kafka) > 0 || len(l7Rules.L7) > 0 {
					ctx.PolicyTrace("   Merge conflict: mismatching L7 rule types.\n")
					return fmt.Errorf("Cannot merge conflicting L7 rule types")
				}

				for _, newRule := range newL7Rules.DNS {
					if !newRule.Exists(l7Rules) {
						l7Rules.DNS = append(l7Rules.DNS, newRule)
					}
				}

			default:
				ctx.PolicyTrace("   No L7 rules to merge.\n")
			}
			existingFilter.L7RulesPerEp[cs] = l7Rules
		} else {
			existingFilter.L7RulesPerEp[cs] = newL7Rules
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
// If any rules contain L7 rules that select Host and we should accept
// all traffic from host (hostWildcardL7 == true) the L7 rules will be
// translated into L7 wildcards (ie, traffic will be forwarded to the
// proxy for endpoints matching those labels, but the proxy will allow
// all such traffic).
func mergeIngressPortProto(ctx *SearchContext, endpoints api.EndpointSelectorSlice, hostWildcardL7 bool, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap, selectorCache *SelectorCache) (int, error) {

	key := p.Port + "/" + string(proto)
	existingFilter, ok := resMap[key]
	if !ok {
		resMap[key] = createL4IngressFilter(endpoints, hostWildcardL7, r, p, proto, ruleLabels, selectorCache)
		return 1, nil
	}

	// Create a new L4Filter based off of the arguments provided to this function
	// for merging with the filter which is already in the policy map.
	filterToMerge := createL4IngressFilter(endpoints, hostWildcardL7, r, p, proto, ruleLabels, selectorCache)

	if err := mergePortProto(ctx, existingFilter, filterToMerge, selectorCache); err != nil {
		filterToMerge.detach(selectorCache)
		return 0, err
	}
	existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	resMap[key] = existingFilter

	return 1, nil
}

func traceL3(ctx *SearchContext, peerEndpoints api.EndpointSelectorSlice, direction string) {
	var result bytes.Buffer

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
			result.WriteString("    Allows ")
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
				Port:     fmt.Sprintf("%d", dp.Port),
				Protocol: api.L4Proto(dp.Protocol),
			}
			if p.Covers(tracePort) {
				return true
			}
		}
	}
	return false
}

func mergeIngress(ctx *SearchContext, fromEndpoints api.EndpointSelectorSlice, toPorts []api.PortRule, ruleLabels labels.LabelArray, resMap L4PolicyMap, selectorCache *SelectorCache) (int, error) {
	found := 0

	if ctx.From != nil && len(fromEndpoints) > 0 {
		if ctx.TraceEnabled() {
			traceL3(ctx, fromEndpoints, "from")
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
	hostWildcardL7 := option.Config.AlwaysAllowLocalhost()

	var (
		cnt int
		err error
	)

	// L3-only rule (with requirements folded into fromEndpoints).
	if len(toPorts) == 0 && len(fromEndpoints) > 0 {
		cnt, err = mergeIngressPortProto(ctx, fromEndpoints, hostWildcardL7, api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap, selectorCache)
		if err != nil {
			return found, err
		}
	}

	found += cnt

	for _, r := range toPorts {
		// For L4 Policy, an empty slice of EndpointSelector indicates that the
		// rule allows all at L3 - explicitly specify this by creating a slice
		// with the WildcardEndpointSelector.
		if len(fromEndpoints) == 0 {
			fromEndpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		}

		ctx.PolicyTrace("      Allows port %v\n", r.Ports)
		if !rulePortsCoverSearchContext(r.Ports, ctx) {
			ctx.PolicyTrace("        No port match found\n")
			continue
		}
		if r.Rules != nil && r.Rules.L7Proto != "" {
			ctx.PolicyTrace("        l7proto: \"%s\"\n", r.Rules.L7Proto)
		}
		if !r.Rules.IsEmpty() {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("          %+v\n", l7)
			}
			for _, l7 := range r.Rules.Kafka {
				ctx.PolicyTrace("          %+v\n", l7)
			}
			for _, l7 := range r.Rules.L7 {
				ctx.PolicyTrace("          %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeIngressPortProto(ctx, fromEndpoints, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap, selectorCache)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err := mergeIngressPortProto(ctx, fromEndpoints, hostWildcardL7, r, p, api.ProtoTCP, ruleLabels, resMap, selectorCache)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeIngressPortProto(ctx, fromEndpoints, hostWildcardL7, r, p, api.ProtoUDP, ruleLabels, resMap, selectorCache)
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

func (state *traceState) unSelectRule(ctx *SearchContext, labels labels.LabelArray, r *rule) {
	ctx.PolicyTraceVerbose("  Rule %s: did not select %+v\n", r, labels)
}

// resolveIngressPolicy analyzes the rule against the given SearchContext, and
// merges it with any prior-generated policy within the provided L4Policy.
// Requirements based off of all Ingress requirements (set in FromRequires) in
// other rules are stored in the specified slice of LabelSelectorRequirement.
// These requirements are dynamically inserted into a copy of the receiver rule,
// as requirements form conjunctions across all rules.
func (r *rule) resolveIngressPolicy(ctx *SearchContext, state *traceState, result *L4Policy, requirements []v1.LabelSelectorRequirement, selectorCache *SelectorCache) (*L4Policy, error) {
	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.To) {
			state.unSelectRule(ctx, ctx.To, r)
			return nil, nil
		}
	}

	state.selectRule(ctx, r)
	found := 0

	if len(r.Ingress) == 0 {
		ctx.PolicyTrace("    No ingress rules\n")
	}
	for _, ingressRule := range r.Ingress {
		fromEndpoints := ingressRule.GetSourceEndpointSelectorsWithRequirements(requirements)
		cnt, err := mergeIngress(ctx, fromEndpoints, ingressRule.ToPorts, r.Rule.Labels.DeepCopy(), result.Ingress, selectorCache)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			found += cnt
		}
	}

	if found > 0 {
		return result, nil
	}

	return nil, nil
}

// ********************** CIDR POLICY **********************

// mergeCIDR inserts all of the CIDRs in ipRules to resMap. Returns the number
// of CIDRs added to resMap.
func mergeCIDR(ctx *SearchContext, dir string, ipRules []api.CIDR, ruleLabels labels.LabelArray, resMap *CIDRPolicyMap) int {
	found := 0

	for _, r := range ipRules {
		strCIDR := string(r)
		ctx.PolicyTrace("  Allows %s IP %s\n", dir, strCIDR)

		found += resMap.Insert(strCIDR, ruleLabels)
	}

	return found
}

// resolveCIDRPolicy inserts the CIDRs from the specified rule into result if
// the rule corresponds to the current SearchContext. It returns the resultant
// CIDRPolicy containing the added ingress and egress CIDRs. If no CIDRs are
// added to result, a nil CIDRPolicy is returned.
func (r *rule) resolveCIDRPolicy(ctx *SearchContext, state *traceState, result *CIDRPolicy) *CIDRPolicy {
	// Don't select rule if it doesn't apply to the given context.
	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.To) {
			state.unSelectRule(ctx, ctx.To, r)
			return nil
		}
	}

	state.selectRule(ctx, r)
	found := 0

	for _, ingressRule := range r.Ingress {
		// TODO (ianvernon): GH-1658
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, ingressRule.FromCIDR...)
		allCIDRs = append(allCIDRs, api.ComputeResultantCIDRSet(ingressRule.FromCIDRSet)...)

		// CIDR + L4 rules are handled via mergeIngress(),
		// skip them here.
		if len(allCIDRs) > 0 && len(ingressRule.ToPorts) > 0 {
			continue
		}

		if cnt := mergeCIDR(ctx, "Ingress", allCIDRs, r.Labels, &result.Ingress); cnt > 0 {
			found += cnt
		}
	}

	// CIDR egress policy is used for visibility of desired state in
	// the API and for determining which prefix lengths are available,
	// however it does not determine the actual CIDRs in the BPF maps
	// for allowing traffic by CIDR!
	for _, egressRule := range r.Egress {
		var allCIDRs []api.CIDR
		allCIDRs = append(allCIDRs, egressRule.ToCIDR...)
		allCIDRs = append(allCIDRs, api.ComputeResultantCIDRSet(egressRule.ToCIDRSet)...)

		// Unlike the Ingress policy which only counts L3 policy in
		// this function, we count the CIDR+L4 policy in the
		// desired egress CIDR policy here as well. This ensures
		// proper computation of IPcache prefix lengths.
		if cnt := mergeCIDR(ctx, "Egress", allCIDRs, r.Labels, &result.Egress); cnt > 0 {
			found += cnt
		}
	}

	if found > 0 {
		return result
	}

	ctx.PolicyTrace("    No L3 rules\n")
	return nil
}

func (r *rule) matches(securityIdentity *identity.Identity) bool {
	r.metadata.Mutex.Lock()
	defer r.metadata.Mutex.Unlock()
	var ruleMatches bool

	if ruleMatches, cached := r.metadata.IdentitySelected[securityIdentity.ID]; cached {
		return ruleMatches
	}
	// Fall back to costly matching.
	if ruleMatches = r.EndpointSelector.Matches(securityIdentity.LabelArray); ruleMatches {
		// Update cache so we don't have to do costly matching again.
		r.metadata.IdentitySelected[securityIdentity.ID] = true
	} else {
		r.metadata.IdentitySelected[securityIdentity.ID] = false
	}

	return ruleMatches
}

// ****************** EGRESS POLICY ******************

func mergeEgress(ctx *SearchContext, toEndpoints api.EndpointSelectorSlice, toPorts []api.PortRule, ruleLabels labels.LabelArray, resMap L4PolicyMap, selectorCache *SelectorCache, fqdns api.FQDNSelectorSlice) (int, error) {
	found := 0

	if ctx.To != nil && len(toEndpoints) > 0 {
		if ctx.TraceEnabled() {
			traceL3(ctx, toEndpoints, "to")
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
	if len(toPorts) == 0 && len(toEndpoints) > 0 {
		cnt, err = mergeEgressPortProto(ctx, toEndpoints, api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap, selectorCache, fqdns)
		if err != nil {
			return found, err
		}
	}

	found += cnt

	for _, r := range toPorts {
		// For L4 Policy, an empty slice of EndpointSelector indicates that the
		// rule allows all at L3 - explicitly specify this by creating a slice
		// with the WildcardEndpointSelector.
		if len(toEndpoints) == 0 {
			toEndpoints = api.EndpointSelectorSlice{api.WildcardEndpointSelector}
		}
		ctx.PolicyTrace("      Allows port %v\n", r.Ports)
		if r.Rules != nil && r.Rules.L7Proto != "" {
			ctx.PolicyTrace("        l7proto: \"%s\"\n", r.Rules.L7Proto)
		}
		if !r.Rules.IsEmpty() {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("          %+v\n", l7)
			}
			for _, l7 := range r.Rules.Kafka {
				ctx.PolicyTrace("          %+v\n", l7)
			}
			for _, l7 := range r.Rules.L7 {
				ctx.PolicyTrace("          %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != api.ProtoAny {
				cnt, err := mergeEgressPortProto(ctx, toEndpoints, r, p, p.Protocol, ruleLabels, resMap, selectorCache, fqdns)
				if err != nil {
					return found, err
				}
				found += cnt
			} else {
				cnt, err := mergeEgressPortProto(ctx, toEndpoints, r, p, api.ProtoTCP, ruleLabels, resMap, selectorCache, fqdns)
				if err != nil {
					return found, err
				}
				found += cnt

				cnt, err = mergeEgressPortProto(ctx, toEndpoints, r, p, api.ProtoUDP, ruleLabels, resMap, selectorCache, fqdns)
				if err != nil {
					return found, err
				}
				found += cnt
			}
		}
	}

	return found, nil
}

// mergeEgressPortProto merges all rules which share the same port & protocol that
// select a given set of endpoints. It updates the L4Filter mapped to by the specified
// port and protocol with the contents of the provided PortRule. If the rule
// being merged has conflicting L7 rules with those already in the provided
// L4PolicyMap for the specified port-protocol tuple, it returns an error.
func mergeEgressPortProto(ctx *SearchContext, endpoints api.EndpointSelectorSlice, r api.PortRule, p api.PortProtocol,
	proto api.L4Proto, ruleLabels labels.LabelArray, resMap L4PolicyMap, selectorCache *SelectorCache, fqdns api.FQDNSelectorSlice) (int, error) {

	key := p.Port + "/" + string(proto)
	existingFilter, ok := resMap[key]
	if !ok {
		resMap[key] = createL4EgressFilter(endpoints, r, p, proto, ruleLabels, selectorCache, fqdns)
		return 1, nil
	}

	// Create a new L4Filter based off of the arguments provided to this function
	// for merging with the filter which is already in the policy map.
	filterToMerge := createL4EgressFilter(endpoints, r, p, proto, ruleLabels, selectorCache, fqdns)

	if err := mergePortProto(ctx, existingFilter, filterToMerge, selectorCache); err != nil {
		filterToMerge.detach(selectorCache)
		return 0, err
	}
	existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	resMap[key] = existingFilter
	return 1, nil
}

func (r *rule) resolveEgressPolicy(ctx *SearchContext, state *traceState, result *L4Policy, requirements []v1.LabelSelectorRequirement, selectorCache *SelectorCache) (*L4Policy, error) {
	if !ctx.rulesSelect {
		if !r.EndpointSelector.Matches(ctx.From) {
			state.unSelectRule(ctx, ctx.From, r)
			return nil, nil
		}
	}

	state.selectRule(ctx, r)
	found := 0

	if len(r.Egress) == 0 {
		ctx.PolicyTrace("    No L4 rules\n")
	}
	for _, egressRule := range r.Egress {
		toEndpoints := egressRule.GetDestinationEndpointSelectorsWithRequirements(requirements)
		cnt, err := mergeEgress(ctx, toEndpoints, egressRule.ToPorts, r.Rule.Labels.DeepCopy(), result.Egress, selectorCache, egressRule.ToFQDNs)
		if err != nil {
			return nil, err
		}
		if cnt > 0 {
			found += cnt
		}
	}

	if found > 0 {
		return result, nil
	}

	return nil, nil
}
