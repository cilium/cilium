// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_cors_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/utils/ptr"

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
			Name: "exact match long with POST method",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/longest",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: ":method",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "POST",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "exact match long with GET method",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/exact/match/longest",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: ":method",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "GET",
								},
							},
						},
					},
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
			Name: "prefix match short with HEAD method",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/prefix/match",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: ":method",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "HEAD",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "prefix match short with GET method",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
					PathSeparatedPrefix: "/prefix/match",
				},
				Headers: []*envoy_config_route_v3.HeaderMatcher{
					{
						Name: ":method",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_type_matcher_v3.StringMatcher{
								MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
									Exact: "GET",
								},
							},
						},
					},
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
		"exact match long with POST method",
		"exact match long with GET method",
		"exact match with one header",
		"exact match with one header and one query",
		"exact match with two headers",
		"prefix match short",
		"prefix match short with HEAD method",
		"prefix match short with GET method",
		"prefix match long",
		"prefix match with one header",
		"prefix match with one header and one query",
		"prefix match with two headers",
	}, namesBeforeSort)

	sort.Sort(arr)

	namesAfterSort := buildNameSlice(arr)
	assert.Equal(t, []string{
		"exact match long with GET method",
		"exact match long with POST method",
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
		"prefix match short with GET method",
		"prefix match short with HEAD method",
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
			HostName: ptr.To("example.com"),
		}

		res := hostRewriteMutation(rewrite)(route)
		require.Equal(t, &envoy_config_route_v3.RouteAction_HostRewriteLiteral{
			HostRewriteLiteral: "example.com",
		}, res.Route.HostRewriteSpecifier)
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
		require.Equal(t, "/prefix", res.Route.PrefixRewrite)
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
		require.Equal(t, &envoy_type_matcher_v3.RegexMatchAndSubstitute{
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
		require.Equal(t, &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				Regex: fmt.Sprintf(`^%s(/?)(.*)`, regexp.QuoteMeta(httpRoute.PathMatch.Prefix)),
			},
			Substitution: `/\2`,
		}, res.Route.RegexRewrite)
	})
	t.Run("with root path and prefix rewrite", func(t *testing.T) {
		httpRoute := model.HTTPRoute{}
		httpRoute.PathMatch.Prefix = "/"
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		rewrite := &model.HTTPURLRewriteFilter{
			Path: &model.StringMatch{
				Prefix: "/prefix/",
			},
		}

		res := pathPrefixMutation(rewrite, &httpRoute)(route)
		require.Equal(t, &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				Regex: `^/(.*)`,
			},
			Substitution: strings.TrimSuffix(rewrite.Path.Prefix, "/") + `/\1`,
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
				Numerator:   100,
				Denominator: 100,
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
				Numerator:   100,
				Denominator: 100,
			},
		}

		res := requestMirrorMutation(mirror)(route)
		require.Len(t, res.Route.RequestMirrorPolicies, 2)
		require.Equal(t, "default:dummy-service:8080", res.Route.RequestMirrorPolicies[0].Cluster)
		require.Equal(t, uint32(100), res.Route.RequestMirrorPolicies[0].RuntimeFraction.DefaultValue.Numerator)
		require.Equal(t, "default:another-dummy-service:8080", res.Route.RequestMirrorPolicies[1].Cluster)
		require.Equal(t, uint32(100), res.Route.RequestMirrorPolicies[1].RuntimeFraction.DefaultValue.Numerator)
	})
}

func Test_retryMutation(t *testing.T) {
	t.Run("no retry", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		res := retryMutation(nil)(route)
		require.Equal(t, route, res)
	})

	t.Run("with retry without backoff", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		retry := &model.HTTPRetry{
			Codes:    []uint32{500, 503},
			Attempts: ptr.To(3),
		}

		res := retryMutation(retry)(route)
		require.Equal(t, "retriable-status-codes,connect-failure,reset,refused-stream", res.Route.RetryPolicy.RetryOn)
		require.Equal(t, []uint32{500, 503}, res.Route.RetryPolicy.RetriableStatusCodes)
		require.Empty(t, res.Route.RetryPolicy.RetryBackOff)
		require.Equal(t, uint32(3), res.Route.RetryPolicy.NumRetries.Value)
	})

	t.Run("with retry with backoff", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		retry := &model.HTTPRetry{
			Codes:    []uint32{500, 503},
			Attempts: ptr.To(3),
			Backoff:  ptr.To(10 * time.Second),
		}

		res := retryMutation(retry)(route)
		require.Equal(t, "retriable-status-codes,connect-failure,reset,refused-stream", res.Route.RetryPolicy.RetryOn)
		require.Equal(t, []uint32{500, 503}, res.Route.RetryPolicy.RetriableStatusCodes)
		require.Equal(t, uint32(3), res.Route.RetryPolicy.NumRetries.Value)
		require.NotEmpty(t, res.Route.RetryPolicy.RetryBackOff)
		require.Equal(t, int64(10), res.Route.RetryPolicy.RetryBackOff.BaseInterval.Seconds)
		require.Equal(t, int64(20), res.Route.RetryPolicy.RetryBackOff.MaxInterval.Seconds)
	})

	t.Run("with retry without codes still retries on connection errors", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		retry := &model.HTTPRetry{
			Attempts: ptr.To(3),
		}

		res := retryMutation(retry)(route)
		// Per GEP-1731, a configured retry stanza should retry connection errors
		// even when no status codes are specified.
		require.Equal(t, "retriable-status-codes,connect-failure,reset,refused-stream", res.Route.RetryPolicy.RetryOn)
		require.Empty(t, res.Route.RetryPolicy.RetriableStatusCodes)
		require.Equal(t, uint32(3), res.Route.RetryPolicy.NumRetries.Value)
	})

	t.Run("with retry without attempts leaves num_retries unset", func(t *testing.T) {
		route := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{},
		}
		retry := &model.HTTPRetry{
			Codes: []uint32{503},
		}

		res := retryMutation(retry)(route)
		require.Equal(t, "retriable-status-codes,connect-failure,reset,refused-stream", res.Route.RetryPolicy.RetryOn)
		require.Equal(t, []uint32{503}, res.Route.RetryPolicy.RetriableStatusCodes)
		// Attempts unset -> NumRetries stays nil in the generated config; Envoy
		// applies its own default of 1 at runtime.
		require.Nil(t, res.Route.RetryPolicy.NumRetries)
	})
}

func Test_envoyHTTPRoutes(t *testing.T) {
	backend := func(name string, port uint32) model.Backend {
		return model.Backend{
			Name:      name,
			Namespace: "default",
			Port:      &model.BackendPort{Port: port},
		}
	}
	sourceRule := func(ruleIndex int) *model.HTTPRouteRule {
		return &model.HTTPRouteRule{
			Source: model.FullyQualifiedResource{
				Name:      "route",
				Namespace: "default",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1",
				Kind:      "HTTPRoute",
			},
			RuleIndex: ruleIndex,
		}
	}

	t.Run("redirect with x-forwarded-proto and backend", func(t *testing.T) {
		httpRoutes := []model.HTTPRoute{
			{
				Name:      "Redirect",
				PathMatch: model.StringMatch{Prefix: "/"},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					Scheme:     ptr.To("https"),
					Port:       ptr.To(int32(443)),
					StatusCode: ptr.To(302),
				},
			},
			{
				Name:      "Backend",
				PathMatch: model.StringMatch{Prefix: "/"},
				Backends: []model.Backend{
					{
						Name:      "backend",
						Namespace: "default",
						Port:      &model.BackendPort{Port: 31337},
					},
				},
			},
		}
		res := envoyHTTPRoutes(httpRoutes, []string{"*"}, true, 80, nil)
		require.Len(t, res, 2)
		// Redirect Route
		require.NotNil(t, res[0])
		require.Equal(t, "/", res[0].Match.GetPrefix())
		require.Len(t, res[0].Match.GetHeaders(), 1)
		require.Equal(t, "X-Forwarded-Proto", res[0].Match.GetHeaders()[0].Name)
		require.True(t, res[0].Match.GetHeaders()[0].InvertMatch)
		require.Equal(t, "https", res[0].Match.GetHeaders()[0].GetStringMatch().GetExact())
		require.NotNil(t, res[0].GetRedirect())
		require.Equal(t, "https", res[0].GetRedirect().GetSchemeRedirect())
		require.Equal(t, uint32(443), res[0].GetRedirect().PortRedirect)
		require.Equal(t, envoy_config_route_v3.RedirectAction_FOUND, res[0].GetRedirect().ResponseCode)
		// Backend Route
		require.NotNil(t, res[1])
		require.Equal(t, "/", res[1].Match.GetPrefix())
		require.Empty(t, res[1].Match.GetHeaders())
		require.NotNil(t, res[1].GetRoute())
		require.Equal(t, "default:backend:31337", res[1].GetRoute().GetCluster())
	})
	t.Run("http route with CORS filter and no backend", func(t *testing.T) {
		corsPolicy := toAny(&envoy_extensions_filters_http_cors_v3.CorsPolicy{
			AllowOriginStringMatch: []*envoy_type_matcher_v3.StringMatcher{
				{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: "https://example.com",
					},
				},
			},
			AllowCredentials:             wrapperspb.Bool(false),
			AllowMethods:                 "*",
			AllowHeaders:                 "*",
			ExposeHeaders:                "*",
			MaxAge:                       "42",
			ForwardNotMatchingPreflights: wrapperspb.Bool(false),
		})
		httpRoutes := []model.HTTPRoute{
			{
				Name:      "Index",
				PathMatch: model.StringMatch{Prefix: "/"},
				DirectResponse: &model.DirectResponse{
					StatusCode: 500,
				},
				CORS: &model.HTTPCORSFilter{
					AllowOrigins:  []string{"https://example.com"},
					AllowMethods:  []string{"*"},
					AllowHeaders:  []string{"*"},
					ExposeHeaders: []string{"*"},
					MaxAge:        42,
				},
			},
		}
		res := envoyHTTPRoutes(httpRoutes, []string{"*"}, true, 80, nil)
		require.Len(t, res, 1)
		require.NotNil(t, res[0])
		require.NotNil(t, res[0].GetDirectResponse())
		require.Equal(t, uint32(500), res[0].GetDirectResponse().GetStatus())
		require.Equal(t, corsPolicy, res[0].GetTypedPerFilterConfig()["envoy.filters.http.cors"])
	})
	t.Run("legacy same-match routes aggregate backends", func(t *testing.T) {
		httpRoutes := []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/same-path"},
				Backends: []model.Backend{
					backend("backend-v1", 8080),
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/same-path"},
				Backends: []model.Backend{
					backend("backend-v2", 8080),
				},
			},
		}

		res := envoyHTTPRoutes(httpRoutes, []string{"*"}, true, 80, nil)

		require.Len(t, res, 1)
		weightedClusters := res[0].GetRoute().GetWeightedClusters()
		require.NotNil(t, weightedClusters)
		require.Len(t, weightedClusters.GetClusters(), 2)
		require.Equal(t, "default:backend-v1:8080", weightedClusters.GetClusters()[0].GetName())
		require.Equal(t, "default:backend-v2:8080", weightedClusters.GetClusters()[1].GetName())
	})
	t.Run("gateway same-match rules remain separate", func(t *testing.T) {
		httpRoutes := []model.HTTPRoute{
			{
				SourceRule: sourceRule(0),
				PathMatch:  model.StringMatch{Exact: "/same-path"},
				Backends: []model.Backend{
					backend("backend-v1", 8080),
				},
			},
			{
				SourceRule: sourceRule(1),
				PathMatch:  model.StringMatch{Exact: "/same-path"},
				Backends: []model.Backend{
					backend("backend-v2", 8080),
				},
			},
		}

		res := envoyHTTPRoutes(httpRoutes, []string{"*"}, true, 80, nil)

		require.Len(t, res, 2)
		require.Equal(t, "default:backend-v1:8080", res[0].GetRoute().GetCluster())
		require.Equal(t, "default:backend-v2:8080", res[1].GetRoute().GetCluster())
	})
	t.Run("gateway first same-match rule with missing backend returns direct response", func(t *testing.T) {
		httpRoutes := []model.HTTPRoute{
			{
				SourceRule: sourceRule(0),
				PathMatch:  model.StringMatch{Exact: "/same-path"},
				DirectResponse: &model.DirectResponse{
					StatusCode: 500,
				},
			},
			{
				SourceRule: sourceRule(1),
				PathMatch:  model.StringMatch{Exact: "/same-path"},
				Backends: []model.Backend{
					backend("backend-v2", 8080),
				},
			},
		}

		res := envoyHTTPRoutes(httpRoutes, []string{"*"}, true, 80, nil)

		require.Len(t, res, 2)
		require.NotNil(t, res[0].GetDirectResponse())
		require.Equal(t, uint32(500), res[0].GetDirectResponse().GetStatus())
		require.Equal(t, "default:backend-v2:8080", res[1].GetRoute().GetCluster())
	})
}

// Test_envoyHTTPSRoutes_disablesExtAuthzFilters verifies that HTTPS redirect routes
// explicitly disable any ext_authz filters present on the listener. Without this,
// redirect routes on a mixed listener inherit auth enforcement, which is incorrect.
func Test_envoyHTTPSRoutes_disablesExtAuthzFilters(t *testing.T) {
	authFilters := []*model.HTTPExternalAuthFilter{
		{Backend: model.Backend{Name: "authz", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}, Protocol: model.ExternalAuthProtocolGRPC},
	}
	routes := []model.HTTPRoute{
		{PathMatch: model.StringMatch{Prefix: "/"}},
	}

	result := envoyHTTPSRoutes(routes, []string{"example.com"}, false, authFilters)
	require.Len(t, result, 1)

	// The redirect route must disable all auth filters so that redirect requests
	// are not sent to the auth server before being redirected.
	require.NotNil(t, result[0].TypedPerFilterConfig, "HTTPS redirect route must have TypedPerFilterConfig to disable ext_authz filters")
	filterName := ExtAuthzFilterName("GRPC:ns:authz:9000")
	entry, ok := result[0].TypedPerFilterConfig[filterName]
	require.True(t, ok, "expected ext_authz filter to be disabled on redirect route")
	perRoute := &extauthzv3.ExtAuthzPerRoute{}
	require.NoError(t, proto.Unmarshal(entry.Value, perRoute))
	require.True(t, perRoute.GetDisabled())
}

// Test_envoyHTTPRoutes_differentAuthFilters verifies that two routes with identical
// path matches but different ExternalAuth backends are not merged. Without ExternalAuth
// in the match key, only hRoutes[0]'s auth config would survive the merge.
func Test_envoyHTTPRoutes_differentAuthFilters(t *testing.T) {
	authA := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "authz-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}},
		Protocol: model.ExternalAuthProtocolGRPC,
	}
	authB := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "authz-b", Namespace: "ns", Port: &model.BackendPort{Port: 9001}},
		Protocol: model.ExternalAuthProtocolGRPC,
	}
	allAuthFilters := []*model.HTTPExternalAuthFilter{authA, authB}

	httpRoutes := []model.HTTPRoute{
		{
			PathMatch:    model.StringMatch{Prefix: "/"},
			ExternalAuth: authA,
			Backends: []model.Backend{
				{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 80}},
			},
		},
		{
			PathMatch:    model.StringMatch{Prefix: "/"},
			ExternalAuth: authB,
			Backends: []model.Backend{
				{Name: "svc-b", Namespace: "ns", Port: &model.BackendPort{Port: 80}},
			},
		},
	}

	res := envoyHTTPRoutes(httpRoutes, []string{"*"}, false, 80, allAuthFilters)
	require.Len(t, res, 2, "routes with different auth filters must not be merged")

	filterNameA := ExtAuthzFilterName(extAuthzFilterKey(authA))
	filterNameB := ExtAuthzFilterName(extAuthzFilterKey(authB))

	// First route uses authA — authB must be disabled on it, authA must not appear (enabled by default).
	cfgA := res[0].TypedPerFilterConfig
	require.NotNil(t, cfgA)
	_, hasA := cfgA[filterNameA]
	require.False(t, hasA, "authA filter must be active (not disabled) on route 0")
	perRouteB0 := &extauthzv3.ExtAuthzPerRoute{}
	require.NoError(t, proto.Unmarshal(cfgA[filterNameB].Value, perRouteB0))
	require.True(t, perRouteB0.GetDisabled(), "authB filter must be disabled on route 0")

	// Second route uses authB — authA must be disabled on it, authB must not appear (enabled by default).
	cfgB := res[1].TypedPerFilterConfig
	require.NotNil(t, cfgB)
	perRouteA1 := &extauthzv3.ExtAuthzPerRoute{}
	require.NoError(t, proto.Unmarshal(cfgB[filterNameA].Value, perRouteA1))
	require.True(t, perRouteA1.GetDisabled(), "authA filter must be disabled on route 1")
	_, hasB := cfgB[filterNameB]
	require.False(t, hasB, "authB filter must be active (not disabled) on route 1")
}

func Test_envoyHTTPSRoutes_noAuthFilters(t *testing.T) {
	routes := []model.HTTPRoute{
		{PathMatch: model.StringMatch{Prefix: "/"}},
	}
	result := envoyHTTPSRoutes(routes, []string{"example.com"}, false, nil)
	require.Len(t, result, 1)
	require.Nil(t, result[0].TypedPerFilterConfig, "redirect route must not set TypedPerFilterConfig when there are no auth filters")
}

func Test_getCORSStringMatcher(t *testing.T) {
	t.Run("exact match no wildcard", func(t *testing.T) {
		ao := "http://example.com"
		match := &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: ao,
			},
		}
		res := getCORSStringMatcher(ao)
		require.Equal(t, match, res)
	})
	t.Run("wildcard only match", func(t *testing.T) {
		ao := "*"
		match := &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^.*$",
				},
			},
		}
		res := getCORSStringMatcher(ao)
		require.Equal(t, match, res)
	})
	t.Run("wildcard match", func(t *testing.T) {
		ao := "http://*.example.com"
		match := &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^http://[A-Za-z0-9.-]+\\.example\\.com$",
				},
			},
		}
		res := getCORSStringMatcher(ao)
		require.Equal(t, match, res)
	})
}

func Test_getCORS(t *testing.T) {
	t.Run("allow and expose all", func(t *testing.T) {
		cf := &model.HTTPCORSFilter{
			AllowOrigins:     []string{"*"},
			AllowCredentials: false,
			AllowMethods:     []string{"*"},
			AllowHeaders:     []string{"*"},
			ExposeHeaders:    []string{"*"},
			MaxAge:           42,
		}
		res := getCORS(cf)
		match := toAny(&envoy_extensions_filters_http_cors_v3.CorsPolicy{
			AllowOriginStringMatch: []*envoy_type_matcher_v3.StringMatcher{
				{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
							Regex: "^.*$",
						},
					},
				},
			},
			AllowCredentials:             wrapperspb.Bool(false),
			AllowMethods:                 "*",
			AllowHeaders:                 "*",
			ExposeHeaders:                "*",
			MaxAge:                       "42",
			ForwardNotMatchingPreflights: wrapperspb.Bool(false),
		})
		require.NotNil(t, res)
		require.Equal(t, match, res)
	})
	t.Run("allow specific methods and headers", func(t *testing.T) {
		cf := &model.HTTPCORSFilter{
			AllowOrigins:     []string{"http://example.com", "http://*.example.com"},
			AllowCredentials: false,
			AllowMethods:     []string{"PUT", "GET"},
			AllowHeaders:     []string{"Keep-Alive", "User-Agent"},
			ExposeHeaders:    []string{"Content-Security-Policy"},
			MaxAge:           42,
		}
		res := getCORS(cf)
		match := toAny(&envoy_extensions_filters_http_cors_v3.CorsPolicy{
			AllowOriginStringMatch: []*envoy_type_matcher_v3.StringMatcher{
				{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: "http://example.com",
					},
				},
				{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
							Regex: "^http://[A-Za-z0-9.-]+\\.example\\.com$",
						},
					},
				},
			},
			AllowCredentials:             wrapperspb.Bool(false),
			AllowMethods:                 "PUT, GET",
			AllowHeaders:                 "Keep-Alive, User-Agent",
			ExposeHeaders:                "Content-Security-Policy",
			MaxAge:                       "42",
			ForwardNotMatchingPreflights: wrapperspb.Bool(false),
		})
		require.NotNil(t, res)
		require.Equal(t, match, res)
	})
}
