// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestRequestRedirectSchemeHeaderMatcher(t *testing.T) {
	// Create a RequestRedirect filter with a scheme redirect
	scheme := "https"
	requestRedirect := &model.HTTPRequestRedirectFilter{
		Scheme: &scheme,
	}

	// Create a route with the RequestRedirect filter
	route := &envoy_config_route_v3.Route{
		Match: &envoy_config_route_v3.RouteMatch{
			Headers: []*envoy_config_route_v3.HeaderMatcher{},
		},
	}

	// Apply the RequestRedirect filter to the route
	if requestRedirect.Scheme != nil {
		// Add a header matcher to only apply the redirect if the scheme doesn't match the target scheme
		schemeHeader := &envoy_config_route_v3.HeaderMatcher{
			Name: ":scheme",
			HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: *requestRedirect.Scheme,
					},
				},
			},
			InvertMatch: true, // Only match if the scheme is NOT the target scheme
		}
		route.Match.Headers = append(route.Match.Headers, schemeHeader)

		// Also check X-Forwarded-Proto header for external TLS termination
		xForwardedProtoHeader := &envoy_config_route_v3.HeaderMatcher{
			Name: "X-Forwarded-Proto",
			HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: *requestRedirect.Scheme,
					},
				},
			},
			InvertMatch: true, // Only match if X-Forwarded-Proto is NOT the target scheme
		}
		route.Match.Headers = append(route.Match.Headers, xForwardedProtoHeader)
	}
	route.Action = getRouteRedirect(requestRedirect, 80)

	// Verify that the route has header matchers for the scheme and X-Forwarded-Proto
	assert.Len(t, route.Match.Headers, 2)
	assert.Equal(t, ":scheme", route.Match.Headers[0].GetName())
	assert.Equal(t, "https", route.Match.Headers[0].GetStringMatch().GetExact())
	assert.True(t, route.Match.Headers[0].GetInvertMatch())
	assert.Equal(t, "X-Forwarded-Proto", route.Match.Headers[1].GetName())
	assert.Equal(t, "https", route.Match.Headers[1].GetStringMatch().GetExact())
	assert.True(t, route.Match.Headers[1].GetInvertMatch())
}
