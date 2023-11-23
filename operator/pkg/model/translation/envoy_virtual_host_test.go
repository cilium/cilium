// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"regexp"
	"sort"
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestSortableRoute(t *testing.T) {
	arr := SortableRoute{
		{
			Name: "regex match short",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						Regex: "/.*",
					},
				},
			},
		},
		{
			Name: "regex match long",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						Regex: "/regex/.*/long",
					},
				},
			},
		},
		{
			Name: "regex match with one header",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						Regex: "/regex",
					},
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "regex match with one header and one query",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						Regex: "/regex",
					},
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
				},
				QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
					{
						Name: "query1",
						QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_PresentMatch{
							PresentMatch: true,
						},
					},
				},
			},
		},

		{
			Name: "regex match with two headers",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						Regex: "/regex",
					},
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
					{
						Name: "header2",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value2",
								},
							},
						},
					},
				},
			},
		},

		{
			Name: "exact match short",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match",
				},
			},
		},
		{
			Name: "exact match long",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/longest",
				},
			},
		},
		{
			Name: "exact match with one header",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/header",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "exact match with one header and one query",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/header",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
				},
				QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
					{
						Name: "query1",
						QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_PresentMatch{
							PresentMatch: true,
						},
					},
				},
			},
		},
		{
			Name: "exact match with two headers",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/header",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
					{
						Name: "header2",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value2",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "prefix match short",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/prefix/match",
				},
			},
		},
		{
			Name: "prefix match long",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/prefix/match/long",
				},
			},
		},
		{
			Name: "prefix match with one header",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/header",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "prefix match with one header and one query",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/header",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
				},
				QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
					{
						Name: "query1",
						QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_PresentMatch{
							PresentMatch: true,
						},
					},
				},
			},
		},
		{
			Name: "prefix match with two headers",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/header",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: "header1",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value1",
								},
							},
						},
					},
					{
						Name: "header2",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "value2",
								},
							},
						},
					},
				},
			},
		},
	}

	// This assertion is to it easier to tell how
	// the array is rearranged by the sorting.
	// It also effectively ensures that buildNameSlice is
	// working correctly.
	namesBeforeSort := buildNameSlice(arr)
	assert.Equal(t, []string{
		"regex match short",
		"regex match long",
		"regex match with one header",
		"regex match with one header and one query",
		"regex match with two headers",
		"exact match short",
		"exact match long",
		"exact match with one header",
		"exact match with one header and one query",
		"exact match with two headers",
		"prefix match short",
		"prefix match long",
		"prefix match with one header",
		"prefix match with one header and one query",
		"prefix match with two headers",
	}, namesBeforeSort)

	sort.Sort(arr)

	namesAfterSort := buildNameSlice(arr)
	assert.Equal(t, []string{
		"exact match long",
		"exact match with two headers",
		"exact match with one header and one query",
		"exact match with one header",
		"exact match short",
		"regex match long",
		"regex match with two headers",
		"regex match with one header and one query",
		"regex match with one header",
		"regex match short",
		"prefix match long",
		"prefix match short",
		"prefix match with two headers",
		"prefix match with one header and one query",
		"prefix match with one header",
	}, namesAfterSort)

}

func buildNameSlice(arr []*envoy_config_route_v3.Route) []string {

	var names []string

	for _, entry := range arr {
		names = append(names, entry.Name)
	}

	return names
}

func Test_hostRewriteMutation(t *testing.T) {
	t.Run("no host rewrite", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		res := hostRewriteMutation(nil)(route)
		require.Equal(t, route, res)
	})

	t.Run("with host rewrite", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		rewrite := &model.HTTPURLRewriteFilter{
			HostName: model.AddressOf("example.com"),
		}

		res := hostRewriteMutation(rewrite)(route)
		require.Equal(t, res.Route.HostRewriteSpecifier, &envoy_config_route_v3.RouteAction_HostRewriteLiteral{
			HostRewriteLiteral: "example.com",
		})
	})
}

func Test_pathPrefixMutation(t *testing.T) {
	t.Run("no prefix rewrite", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		res := pathPrefixMutation(nil, nil)(route)
		require.Equal(t, route, res)
	})

	t.Run("with prefix rewrite", func(t *testing.T) {
		httpRoute := model.HTTPRoute{}
		httpRoute.PathMatch.Prefix = "/strip-prefix"
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		rewrite := &model.HTTPURLRewriteFilter{
			Path: &model.StringMatch{
				Prefix: "/prefix",
			},
		}

		res := pathPrefixMutation(rewrite, &httpRoute)(route)
		require.Equal(t, res.Route.PrefixRewrite, "/prefix")
	})
	t.Run("with empty prefix rewrite", func(t *testing.T) {
		httpRoute := model.HTTPRoute{}
		httpRoute.PathMatch.Prefix = "/strip-prefix"
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		rewrite := &model.HTTPURLRewriteFilter{
			Path: &model.StringMatch{
				Prefix: "",
			},
		}

		res := pathPrefixMutation(rewrite, &httpRoute)(route)
		require.EqualValues(t, &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				Regex: fmt.Sprintf(`^%s(/?)(.*)`, regexp.QuoteMeta(httpRoute.PathMatch.Prefix)),
			},
			Substitution: `/\2`,
		}, res.Route.RegexRewrite)
	})
	t.Run("with slash prefix rewrite", func(t *testing.T) {
		httpRoute := model.HTTPRoute{}
		httpRoute.PathMatch.Prefix = "/strip-prefix"
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		rewrite := &model.HTTPURLRewriteFilter{
			Path: &model.StringMatch{
				Prefix: "/",
			},
		}

		res := pathPrefixMutation(rewrite, &httpRoute)(route)
		require.EqualValues(t, &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				Regex: fmt.Sprintf(`^%s(/?)(.*)`, regexp.QuoteMeta(httpRoute.PathMatch.Prefix)),
			},
			Substitution: `/\2`,
		}, res.Route.RegexRewrite)
	})
}

func Test_requestMirrorMutation(t *testing.T) {
	t.Run("no mirror", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		res := requestMirrorMutation(nil)(route)
		require.Equal(t, route, res)
	})

	t.Run("with mirror", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		mirror := []*model.HTTPRequestMirror{
			{
				Backend: &model.Backend{
					Name:      "dummy-service",
					Namespace: "default",
					Port: &model.BackendPort{
						Port: 8080,
						Name: "http",
					},
				},
			},
			{
				Backend: &model.Backend{
					Name:      "another-dummy-service",
					Namespace: "default",
					Port: &model.BackendPort{
						Port: 8080,
						Name: "http",
					},
				},
			},
		}

		res := requestMirrorMutation(mirror)(route)
		require.Len(t, res.Route.RequestMirrorPolicies, 2)
		require.Equal(t, res.Route.RequestMirrorPolicies[0].Cluster, "default:dummy-service:8080")
		require.Equal(t, res.Route.RequestMirrorPolicies[0].RuntimeFraction.DefaultValue.Numerator, uint32(100))
		require.Equal(t, res.Route.RequestMirrorPolicies[1].Cluster, "default:another-dummy-service:8080")
		require.Equal(t, res.Route.RequestMirrorPolicies[1].RuntimeFraction.DefaultValue.Numerator, uint32(100))
	})
}
