// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoypolicy

import (
	"sort"

	cilium "github.com/cilium/proxy/go/cilium/api"
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
