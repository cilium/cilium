// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"net"
	"sort"
	"strings"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	wildCard       = "*"
	envoyAuthority = ":authority"
	slash          = "/"
	dot            = "."
	starDot        = "*."
	dotRegex       = "[.]"
	notDotRegex    = "[^.]"
)

type VirtualHostMutator func(*envoy_config_route_v3.VirtualHost) *envoy_config_route_v3.VirtualHost

func WithMaxStreamDuration(seconds int64) VirtualHostMutator {
	return func(vh *envoy_config_route_v3.VirtualHost) *envoy_config_route_v3.VirtualHost {
		for _, route := range vh.Routes {
			if route.GetRoute() == nil {
				continue
			}
			route.GetRoute().MaxStreamDuration = &envoy_config_route_v3.RouteAction_MaxStreamDuration{
				MaxStreamDuration: &durationpb.Duration{
					Seconds: seconds,
				},
			}
		}
		return vh
	}
}

// SortableRoute is a slice of envoy Route, which can be sorted based on
// matching order as per Ingress requirement.
//
//   - Exact Match must have the highest priority
//   - If multiple prefix matches are satisfied, the longest path is having
//     higher priority
//
// As Envoy route matching logic is done sequentially, we need to enforce
// such sorting order.
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

// NewVirtualHostWithDefaults is same as NewVirtualHost but with a few
// default mutator function. If there are multiple http routes having
// the same path matching (e.g. exact, prefix or regex), the incoming
// request will be load-balanced to multiple backends equally.
func NewVirtualHostWithDefaults(host string, httpsRedirect bool, httpRoutes []model.HTTPRoute, mutators ...VirtualHostMutator) (*envoy_config_route_v3.VirtualHost, error) {
	fns := append(mutators,
		WithMaxStreamDuration(0),
	)
	return NewVirtualHost(host, httpsRedirect, httpRoutes, fns...)
}

// NewVirtualHost creates a new VirtualHost with the given host and routes.
func NewVirtualHost(host string, httpsRedirect bool, httpRoutes []model.HTTPRoute, mutators ...VirtualHostMutator) (*envoy_config_route_v3.VirtualHost, error) {
	routes := make(SortableRoute, 0, len(httpRoutes))
	matchBackendMap := make(map[model.StringMatch][]model.Backend)

	for _, r := range httpRoutes {
		for _, be := range r.Backends {
			matchBackendMap[r.PathMatch] = append(matchBackendMap[r.PathMatch], be)
		}
	}

	if httpsRedirect {
		for match := range matchBackendMap {
			if httpsRedirect {
				rRedirect := &envoy_config_route_v3.Route_Redirect{
					Redirect: &envoy_config_route_v3.RedirectAction{
						SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
							HttpsRedirect: true,
						},
					},
				}

				route := envoy_config_route_v3.Route{
					Match:  getRouteMatch(host, match),
					Action: rRedirect,
				}
				routes = append(routes, &route)
			}
		}
	} else {
		for match, backends := range matchBackendMap {
			var routeAction *envoy_config_route_v3.Route_Route
			if len(backends) == 1 {
				routeAction = &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: fmt.Sprintf("%s/%s:%s", backends[0].Namespace, backends[0].Name, backends[0].Port.GetPort()),
						},
					},
				}
			} else {
				weightedClusters := make([]*envoy_config_route_v3.WeightedCluster_ClusterWeight, 0, len(backends))
				for _, be := range backends {
					weightedClusters = append(weightedClusters, &envoy_config_route_v3.WeightedCluster_ClusterWeight{
						Name:   fmt.Sprintf("%s/%s:%s", be.Namespace, be.Name, be.Port.GetPort()),
						Weight: wrapperspb.UInt32(10),
					})
				}
				routeAction = &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_WeightedClusters{
							WeightedClusters: &envoy_config_route_v3.WeightedCluster{
								Clusters:    weightedClusters,
								TotalWeight: wrapperspb.UInt32(uint32(10 * len(backends))),
							},
						},
					},
				}
			}
			route := envoy_config_route_v3.Route{
				Match:  getRouteMatch(host, match),
				Action: routeAction,
			}
			routes = append(routes, &route)
		}
	}

	// This is to make sure that the Exact match is always having higher priority.
	// Each route entry in the virtual host is checked, in order. If there is a
	// match, the route is used and no further route checks are made.
	// Related docs https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/route_matching
	sort.Sort(routes)

	var domains = []string{host}
	if host != wildCard {
		domains = []string{
			host,
			// match authority header with port (e.g. "example.com:80")
			net.JoinHostPort(host, wildCard),
		}
	}

	res := &envoy_config_route_v3.VirtualHost{
		Name:    domains[0],
		Domains: domains,
		Routes:  routes,
	}

	for _, fn := range mutators {
		res = fn(res)
	}

	return res, nil
}

func getRouteMatch(host string, match model.StringMatch) *envoy_config_route_v3.RouteMatch {
	headerMatchers := getHeaderMatchers(host)
	if match.Exact != "" {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: match.Exact,
			},
			Headers: headerMatchers,
		}
	}
	if match.Prefix != "" {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
					Regex:      getMatchingPrefixRegex(match.Prefix),
				},
			},
			Headers: headerMatchers,
		}
	}
	if match.Regex != "" {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
					Regex:      match.Regex,
				},
			},
			Headers: headerMatchers,
		}
	}
	return &envoy_config_route_v3.RouteMatch{
		PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
			Prefix: "/",
		},
		Headers: headerMatchers,
	}
}

func getHeaderMatchers(host string) []*envoy_config_route_v3.HeaderMatcher {
	if len(host) == 0 || host == wildCard || !strings.Contains(host, wildCard) {
		return nil
	}
	// Make sure that wildcard character only match one single dns domain.
	// For example, if host is *.foo.com, baz.bar.foo.com should not match
	return []*envoy_config_route_v3.HeaderMatcher{
		{
			Name: envoyAuthority,
			HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
							EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
							Regex:      getMatchingHeaderRegex(host),
						},
					},
				},
			},
		},
	}
}

// getMatchingPrefixRegex returns safe regex used by envoy to match the
// prefix. By default, prefix matching in envoy will not reject /foobar
// if the original path is only /foo. Hence, conversion with safe regex
// is required.
//
// If the original path is /foo, the returned regex will be /foo(/.*)?$
// - /foo -> matched
// - /foo/ -> matched
// - /foobar -> not matched
func getMatchingPrefixRegex(path string) string {
	removedTrailingSlash := path
	if strings.HasSuffix(path, slash) {
		removedTrailingSlash = removedTrailingSlash[:len(removedTrailingSlash)-1]
	}
	return fmt.Sprintf("%s(/.*)?$", removedTrailingSlash)
}

// getMatchingHeaderRegex is to make sure that one and only one single
// subdomain is matched e.g. For example, *.foo.com should only match
// bar.foo.com but not baz.bar.foo.com
func getMatchingHeaderRegex(host string) string {
	if strings.HasPrefix(host, starDot) {
		return fmt.Sprintf("^%s+%s%s$", notDotRegex, dotRegex, strings.ReplaceAll(host[2:], dot, dotRegex))
	}
	return fmt.Sprintf("^%s$", strings.ReplaceAll(host, dot, dotRegex))
}
