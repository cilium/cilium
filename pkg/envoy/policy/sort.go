// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoypolicy

import (
	"sort"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
)

// PortNetworkPolicySlice implements sort.Interface to sort a slice of
// *cilium.PortNetworkPolicy.
type PortNetworkPolicySlice []*cilium.PortNetworkPolicy

func (s PortNetworkPolicySlice) Len() int {
	return len(s)
}

func (s PortNetworkPolicySlice) Less(i, j int) bool {
	p1, p2 := s[i], s[j]

	switch {
	case p1.Protocol < p2.Protocol:
		return true
	case p1.Protocol > p2.Protocol:
		return false
	}

	switch {
	case p1.Port < p2.Port:
		return true
	case p1.Port > p2.Port:
		return false
	}

	switch {
	case p1.EndPort < p2.EndPort:
		return true
	case p1.EndPort > p2.EndPort:
		return false
	}
	// We don't need to compare rules as
	// (Port, EndPort, Protocol) is unique
	return false
}

func (s PortNetworkPolicySlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// SortPortNetworkPolicies sorts the given slice in place and returns
// the sorted slice for convenience.
func SortPortNetworkPolicies(policies []*cilium.PortNetworkPolicy) []*cilium.PortNetworkPolicy {
	sort.Sort(PortNetworkPolicySlice(policies))
	return policies
}

// SortPortNetworkPolicyRulesMap sorts the given map based on the keys
// and returns the sorted slice of rules.
func SortPortNetworkPolicyRulesMap(rulesMap map[string]*cilium.PortNetworkPolicyRule) []*cilium.PortNetworkPolicyRule {
	if rulesMap == nil {
		return nil
	}
	rulesKeys := make([]string, 0, len(rulesMap))
	for key := range rulesMap {
		rulesKeys = append(rulesKeys, key)
	}
	sort.Strings(rulesKeys)
	rules := make([]*cilium.PortNetworkPolicyRule, 0, len(rulesMap))
	for _, key := range rulesKeys {
		rules = append(rules, rulesMap[key])
	}
	return rules
}

// HTTPNetworkPolicyRuleSlice implements sort.Interface to sort a slice of
// *cilium.HttpNetworkPolicyRule.
type HTTPNetworkPolicyRuleSlice []*cilium.HttpNetworkPolicyRule

// HTTPNetworkPolicyRuleLess reports whether the r1 rule should sort before the
// r2 rule.
func HTTPNetworkPolicyRuleLess(r1, r2 *cilium.HttpNetworkPolicyRule) bool {
	headers1, headers2 := r1.Headers, r2.Headers
	switch {
	case len(headers1) < len(headers2):
		return true
	case len(headers1) > len(headers2):
		return false
	}
	// Assuming that the slices are sorted.
	for idx := range headers1 {
		header1, header2 := headers1[idx], headers2[idx]
		switch {
		case HeaderMatcherLess(header1, header2):
			return true
		case HeaderMatcherLess(header2, header1):
			return false
		}
	}

	// Elements are equal.
	return false
}

func (s HTTPNetworkPolicyRuleSlice) Len() int {
	return len(s)
}

func (s HTTPNetworkPolicyRuleSlice) Less(i, j int) bool {
	return HTTPNetworkPolicyRuleLess(s[i], s[j])
}

func (s HTTPNetworkPolicyRuleSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// SortHTTPNetworkPolicyRules sorts the given slice.
func SortHTTPNetworkPolicyRules(rules []*cilium.HttpNetworkPolicyRule) {
	sort.Sort(HTTPNetworkPolicyRuleSlice(rules))
}

// HeaderMatcherSlice implements sort.Interface to sort a slice of
// *envoy_config_route.HeaderMatcher.
type HeaderMatcherSlice []*envoy_config_route.HeaderMatcher

// HeaderMatcherLess reports whether the m1 matcher should sort before the m2
// matcher.
func HeaderMatcherLess(m1, m2 *envoy_config_route.HeaderMatcher) bool {
	switch {
	case m1.Name < m2.Name:
		return true
	case m1.Name > m2.Name:
		return false
	}

	// Compare the header_match_specifier oneof field, by comparing each
	// possible field in the oneof individually:
	// - exactMatch
	// - regexMatch
	// - rangeMatch
	// - presentMatch
	// - prefixMatch
	// - suffixMatch
	// Use the getters to access the fields and return zero values when they
	// are not set.

	s1 := m1.GetExactMatch()
	s2 := m2.GetExactMatch()
	switch {
	case s1 < s2:
		return true
	case s1 > s2:
		return false
	}

	srm1 := m1.GetSafeRegexMatch()
	srm2 := m2.GetSafeRegexMatch()
	switch {
	case srm1 == nil && srm2 != nil:
		return true
	case srm1 != nil && srm2 == nil:
		return false
	case srm1 != nil && srm2 != nil:
		switch {
		case srm1.Regex < srm2.Regex:
			return true
		case srm1.Regex > srm2.Regex:
			return false
		}
	}

	rm1 := m1.GetRangeMatch()
	rm2 := m2.GetRangeMatch()
	switch {
	case rm1 == nil && rm2 != nil:
		return true
	case rm1 != nil && rm2 == nil:
		return false
	case rm1 != nil && rm2 != nil:
		switch {
		case rm1.Start < rm2.Start:
			return true
		case rm1.Start > rm2.Start:
			return false
		}
		switch {
		case rm1.End < rm2.End:
			return true
		case rm1.End > rm2.End:
			return false
		}
	}

	switch {
	case !m1.GetPresentMatch() && m2.GetPresentMatch():
		return true
	case m1.GetPresentMatch() && !m2.GetPresentMatch():
		return false
	}

	s1 = m1.GetPrefixMatch()
	s2 = m2.GetPrefixMatch()
	switch {
	case s1 < s2:
		return true
	case s1 > s2:
		return false
	}

	s1 = m1.GetSuffixMatch()
	s2 = m2.GetSuffixMatch()
	switch {
	case s1 < s2:
		return true
	case s1 > s2:
		return false
	}

	switch {
	case !m1.InvertMatch && m2.InvertMatch:
		return true
	case m1.InvertMatch && !m2.InvertMatch:
		return false
	}

	// Elements are equal.
	return false
}

func (s HeaderMatcherSlice) Len() int {
	return len(s)
}

func (s HeaderMatcherSlice) Less(i, j int) bool {
	return HeaderMatcherLess(s[i], s[j])
}

func (s HeaderMatcherSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// SortHeaderMatchers sorts the given slice.
func SortHeaderMatchers(headers []*envoy_config_route.HeaderMatcher) {
	sort.Sort(HeaderMatcherSlice(headers))
}
