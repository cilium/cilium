// Copyright 2018 Authors of Cilium
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

package sort

import (
	"sort"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
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

// SortPortNetworkPolicies sorts the given slice.
func SortPortNetworkPolicies(policies []*cilium.PortNetworkPolicy) {
	sort.Sort(PortNetworkPolicySlice(policies))
}

// PortNetworkPolicyRuleSlice implements sort.Interface to sort a slice of
// *cilium.PortNetworkPolicyRuleSlice.
type PortNetworkPolicyRuleSlice []*cilium.PortNetworkPolicyRule

// PortNetworkPolicyRuleLess reports whether the r1 rule should sort before
// the r2 rule.
// L3-L4-only rules are less than L7 rules.
func PortNetworkPolicyRuleLess(r1, r2 *cilium.PortNetworkPolicyRule) bool {

	http1, http2, kafka1, kafka2 := r1.GetHttpRules(), r2.GetHttpRules(), r1.GetKafkaRules(), r2.GetKafkaRules()
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

	switch {
	case kafka1 == nil && kafka2 != nil:
		return true
	case kafka1 != nil && kafka2 == nil:
		return false
	}

	if kafka1 != nil && kafka2 != nil {
		kafkaRules1, kafkaRules2 := kafka1.KafkaRules, kafka2.KafkaRules
		switch {
		case len(kafkaRules1) < len(kafkaRules2):
			return true
		case len(kafkaRules1) > len(kafkaRules2):
			return false
		}
		for idx := range kafkaRules1 {
			kafkaRule1, kafkaRule2 := kafkaRules1[idx], kafkaRules2[idx]
			switch {
			case KafkaNetworkPolicyRuleLess(kafkaRule1, kafkaRule2):
				return true
			case KafkaNetworkPolicyRuleLess(kafkaRule2, kafkaRule1):
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

// SortPortNetworkPolicyRules sorts the given slice.
func SortPortNetworkPolicyRules(rules []*cilium.PortNetworkPolicyRule) {
	sort.Sort(PortNetworkPolicyRuleSlice(rules))
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
// *envoy_api_v2_route.HeaderMatcher.
type HeaderMatcherSlice []*envoy_api_v2_route.HeaderMatcher

// HeaderMatcherLess reports whether the m1 matcher should sort before the m2
// matcher.
func HeaderMatcherLess(m1, m2 *envoy_api_v2_route.HeaderMatcher) bool {
	switch {
	case m1.Name < m2.Name:
		return true
	case m1.Name > m2.Name:
		return false
	}

	switch {
	case m1.Value < m2.Value:
		return true
	case m1.Value > m2.Value:
		return false
	}

	switch {
	// Nil values of Regex are equivalent to 'false' (header is not a regex).
	// So, if m1 is not a regex, and m2 is a regex, m1 < m2.
	case (m1.Regex == nil || !m1.Regex.Value) && (m2.Regex != nil && m2.Regex.Value):
		return true
		// Otherwise, if m1 is a regex, and m2 isn't, m1 > m2.
	case (m1.Regex != nil && m1.Regex.Value) && (m2.Regex == nil || !m2.Regex.Value):
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
func SortHeaderMatchers(headers []*envoy_api_v2_route.HeaderMatcher) {
	sort.Sort(HeaderMatcherSlice(headers))
}

// KafkaNetworkPolicyRuleSlice implements sort.Interface to sort a slice of
// *cilium.KafkaNetworkPolicyRule.
type KafkaNetworkPolicyRuleSlice []*cilium.KafkaNetworkPolicyRule

// KafkaNetworkPolicyRuleLess reports whether the r1 rule should sort before the
// r2 rule.
func KafkaNetworkPolicyRuleLess(r1, r2 *cilium.KafkaNetworkPolicyRule) bool {
	switch {
	case r1.ApiVersion < r2.ApiVersion:
		return true
	case r1.ApiVersion > r2.ApiVersion:
		return false
	}

	switch {
	case r1.ApiKey < r2.ApiKey:
		return true
	case r2.ApiKey > r2.ApiKey:
		return false
	}

	switch {
	case r1.Topic < r2.Topic:
		return true
	case r1.Topic > r2.Topic:
		return false
	}

	switch {
	case r1.ClientId < r2.ClientId:
		return true
	case r1.ClientId > r2.ClientId:
		return false
	}

	// Elements are equal.
	return false
}

func (s KafkaNetworkPolicyRuleSlice) Len() int {
	return len(s)
}

func (s KafkaNetworkPolicyRuleSlice) Less(i, j int) bool {
	return KafkaNetworkPolicyRuleLess(s[i], s[j])
}

func (s KafkaNetworkPolicyRuleSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// SortKafkaNetworkPolicyRules sorts the given slice.
func SortKafkaNetworkPolicyRules(rules []*cilium.KafkaNetworkPolicyRule) {
	sort.Sort(KafkaNetworkPolicyRuleSlice(rules))
}
