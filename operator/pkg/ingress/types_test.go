// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ingress

import (
	"sort"
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"
)

func TestSortableRoute(t *testing.T) {
	arr := SortableRoute{
		{
			Name: "exact match 1",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match",
				},
			},
		},
		{
			Name: "another exact match",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/another",
				},
			},
		},
		{
			Name: "prefix match",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
						Regex:      "/prefix/match",
					},
				},
			},
		},
		{
			Name: "another prefix match",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
						Regex:      "/prefix/match/another",
					},
				},
			},
		},
	}

	sort.Sort(arr)

	// Exact match comes first in any order
	assert.True(t, len(arr[0].Match.GetPath()) != 0)
	assert.True(t, len(arr[1].Match.GetPath()) != 0)

	// Prefix match with longer path comes first
	assert.Equal(t, "/prefix/match/another", arr[2].Match.GetSafeRegex().GetRegex())
	assert.Equal(t, "/prefix/match", arr[3].Match.GetSafeRegex().GetRegex())
}
