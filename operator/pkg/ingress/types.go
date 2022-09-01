// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"

// SortableRoute is a slice of envoy Route, which can be sorted based on matching order as per Ingress requirement.
//
// - Exact Match must have the highest priority
// - If multiple prefix matches are satisfied, the longest path is having higher priority
//
// As Envoy route matching logic is done sequentially, we need to enforce such sorting order.
type SortableRoute []*envoy_config_route_v3.Route

func (s SortableRoute) Len() int {
	return len(s)
}

func (s SortableRoute) Less(i, j int) bool {
	// Make sure Exact Match always comes first
	isExactMatch1 := len(s[i].Match.GetPath()) != 0
	isExactMatch2 := len(s[j].Match.GetPath()) != 0
	if isExactMatch1 {
		return true
	}
	if isExactMatch2 {
		return false
	}

	// Make sure longest Prefix match always comes first
	regexMatch1 := len(s[i].Match.GetSafeRegex().String())
	regexMatch2 := len(s[j].Match.GetSafeRegex().String())
	return regexMatch1 > regexMatch2
}

func (s SortableRoute) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
