// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"sort"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
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

	rules1, rules2 := p1.Rules, p2.Rules
	switch {
	case len(rules1) < len(rules2):
		return true
	case len(rules1) > len(rules2):
		return false
	}
	// Assuming that the slices are sorted.
	for idx := range rules1 {
		r1, r2 := rules1[idx], rules2[idx]
		switch {
		case PortNetworkPolicyRuleLess(r1, r2):
			return true
		case PortNetworkPolicyRuleLess(r2, r1):
			return false
		}
	}

	// Elements are equal.
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

// PortNetworkPolicyRuleSlice implements sort.Interface to sort a slice of
// *cilium.PortNetworkPolicyRuleSlice.
type PortNetworkPolicyRuleSlice []*cilium.PortNetworkPolicyRule

// PortNetworkPolicyRuleLess reports whether the r1 rule should sort before
// the r2 rule.
// L3-L4-only rules are less than L7 rules.
func PortNetworkPolicyRuleLess(r1, r2 *cilium.PortNetworkPolicyRule) bool {
	// TODO: Support Kafka.

	http1, http2 := r1.GetHttpRules(), r2.GetHttpRules()
	switch {
	case http1 == nil && http2 != nil:
		return true
	case http1 != nil && http2 == nil:
		return false
	}

	if http1 != nil && http2 != nil {
		httpRules1, httpRules2 := http1.HttpRules, http2.HttpRules
		switch {
		case len(httpRules1) < len(httpRules2):
			return true
		case len(httpRules1) > len(httpRules2):
			return false
		}
		// Assuming that the slices are sorted.
		for idx := range httpRules1 {
			httpRule1, httpRule2 := httpRules1[idx], httpRules2[idx]
			switch {
			case HTTPNetworkPolicyRuleLess(httpRule1, httpRule2):
				return true
			case HTTPNetworkPolicyRuleLess(httpRule2, httpRule1):
				return false
			}
		}
	}

	remotePolicies1, remotePolicies2 := r1.RemotePolicies, r2.RemotePolicies
	switch {
	case len(remotePolicies1) < len(remotePolicies2):
		return true
	case len(remotePolicies1) > len(remotePolicies2):
		return false
	}
	// Assuming that the slices are sorted.
	for idx := range remotePolicies1 {
		p1, p2 := remotePolicies1[idx], remotePolicies2[idx]
		switch {
		case p1 < p2:
			return true
		case p1 > p2:
			return false
		}
	}

	// Elements are equal.
	return false
}

func (s PortNetworkPolicyRuleSlice) Len() int {
	return len(s)
}

func (s PortNetworkPolicyRuleSlice) Less(i, j int) bool {
	return PortNetworkPolicyRuleLess(s[i], s[j])
}

func (s PortNetworkPolicyRuleSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// SortPortNetworkPolicyRules sorts the given slice in place
// and returns the sorted slice for convenience.
func SortPortNetworkPolicyRules(rules []*cilium.PortNetworkPolicyRule) []*cilium.PortNetworkPolicyRule {
	sort.Sort(PortNetworkPolicyRuleSlice(rules))
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
