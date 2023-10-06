// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"net"
	"sort"
	"strings"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/math"
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
	if isExactMatch1 && isExactMatch2 {
		return len(s[i].Match.GetPath()) > len(s[j].Match.GetPath())
	}
	if isExactMatch1 {
		return true
	}
	if isExactMatch2 {
		return false
	}

	// Make sure longest Prefix match always comes first
	prefixMatch1 := math.IntMax(len(s[i].Match.GetPathSeparatedPrefix()), len(s[i].Match.GetPrefix()))
	prefixMatch2 := math.IntMax(len(s[j].Match.GetPathSeparatedPrefix()), len(s[j].Match.GetPrefix()))
	if prefixMatch1 > prefixMatch2 {
		return true
	} else if prefixMatch1 < prefixMatch2 {
		return false
	}

	// Make sure longest Regex match always comes first
	regexMatch1 := len(s[i].Match.GetSafeRegex().String())
	regexMatch2 := len(s[j].Match.GetSafeRegex().String())
	if regexMatch1 > regexMatch2 {
		return true
	} else if regexMatch1 < regexMatch2 {
		return false
	}

	// Make sure the longest header match always comes first
	headerMatch1 := len(s[i].Match.GetHeaders())
	headerMatch2 := len(s[j].Match.GetHeaders())
	if headerMatch1 > headerMatch2 {
		return true
	} else if headerMatch1 < headerMatch2 {
		return false
	}

	// Make sure the longest query match always comes first
	queryMatch1 := len(s[i].Match.GetQueryParameters())
	queryMatch2 := len(s[j].Match.GetQueryParameters())
	return queryMatch1 > queryMatch2
}

func (s SortableRoute) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// VirtualHostParameter is the parameter for NewVirtualHost
type VirtualHostParameter struct {
	HostNames           []string
	HTTPSRedirect       bool
	HostNameSuffixMatch bool
	ListenerPort        uint32
}

// NewVirtualHostWithDefaults is same as NewVirtualHost but with a few
// default mutator function. If there are multiple http routes having
// the same path matching (e.g. exact, prefix or regex), the incoming
// request will be load-balanced to multiple backends equally.
func NewVirtualHostWithDefaults(httpRoutes []model.HTTPRoute, param VirtualHostParameter, mutators ...VirtualHostMutator) (*envoy_config_route_v3.VirtualHost, error) {
	fns := append(mutators,
		WithMaxStreamDuration(0),
	)
	return NewVirtualHost(httpRoutes, param, fns...)
}

// NewVirtualHost creates a new VirtualHost with the given host and routes.
func NewVirtualHost(httpRoutes []model.HTTPRoute, param VirtualHostParameter, mutators ...VirtualHostMutator) (*envoy_config_route_v3.VirtualHost, error) {
	var routes SortableRoute
	if param.HTTPSRedirect {
		routes = envoyHTTPSRoutes(httpRoutes, param.HostNames, param.HostNameSuffixMatch)
	} else {
		routes = envoyHTTPRoutes(httpRoutes, param.HostNames, param.HostNameSuffixMatch, param.ListenerPort)
	}

	// This is to make sure that the Exact match is always having higher priority.
	// Each route entry in the virtual host is checked, in order. If there is a
	// match, the route is used and no further route checks are made.
	// Related docs https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/route_matching
	sort.Stable(routes)

	var domains []string
	for _, host := range param.HostNames {
		if host == wildCard {
			domains = []string{wildCard}
			break
		}
		domains = append(domains,
			host,
			// match authority header with port (e.g. "example.com:80")
			net.JoinHostPort(host, wildCard),
		)
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

func envoyHTTPSRoutes(httpRoutes []model.HTTPRoute, hostnames []string, hostNameSuffixMatch bool) []*envoy_config_route_v3.Route {
	matchBackendMap := make(map[string][]model.HTTPRoute)
	for _, r := range httpRoutes {
		matchBackendMap[r.GetMatchKey()] = append(matchBackendMap[r.GetMatchKey()], r)
	}

	routes := make([]*envoy_config_route_v3.Route, 0, len(matchBackendMap))
	for _, r := range httpRoutes {
		hRoutes, exists := matchBackendMap[r.GetMatchKey()]
		// if not exists, it means this route is already added to the routes
		if !exists {
			continue
		}
		rRedirect := &envoy_config_route_v3.Route_Redirect{
			Redirect: &envoy_config_route_v3.RedirectAction{
				SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
					HttpsRedirect: true,
				},
			},
		}
		route := envoy_config_route_v3.Route{
			Match: getRouteMatch(hostnames,
				hostNameSuffixMatch,
				hRoutes[0].PathMatch,
				hRoutes[0].QueryParamsMatch,
				hRoutes[0].HeadersMatch,
				hRoutes[0].Method),
			Action: rRedirect,
		}
		routes = append(routes, &route)
		delete(matchBackendMap, r.GetMatchKey())
	}
	return routes
}

func envoyHTTPRoutes(httpRoutes []model.HTTPRoute, hostnames []string, hostNameSuffixMatch bool, listenerPort uint32) []*envoy_config_route_v3.Route {
	matchBackendMap := make(map[string][]model.HTTPRoute)
	for _, r := range httpRoutes {
		matchBackendMap[r.GetMatchKey()] = append(matchBackendMap[r.GetMatchKey()], r)
	}

	routes := make([]*envoy_config_route_v3.Route, 0, len(matchBackendMap))
	for _, r := range httpRoutes {
		hRoutes, exists := matchBackendMap[r.GetMatchKey()]
		if !exists {
			continue
		}
		var backends []model.Backend
		for _, r := range hRoutes {
			backends = append(backends, r.Backends...)
		}

		if len(backends) == 0 && hRoutes[0].RequestRedirect == nil {
			routes = append(routes, envoyHTTPRouteNoBackend(hRoutes[0], hostnames, hostNameSuffixMatch))
			continue
		}

		route := envoy_config_route_v3.Route{
			Match: getRouteMatch(hostnames,
				hostNameSuffixMatch,
				hRoutes[0].PathMatch,
				hRoutes[0].HeadersMatch,
				hRoutes[0].QueryParamsMatch,
				hRoutes[0].Method),
			RequestHeadersToAdd:     getHeadersToAdd(hRoutes[0].RequestHeaderFilter),
			RequestHeadersToRemove:  getHeadersToRemove(hRoutes[0].RequestHeaderFilter),
			ResponseHeadersToAdd:    getHeadersToAdd(hRoutes[0].ResponseHeaderModifier),
			ResponseHeadersToRemove: getHeadersToRemove(hRoutes[0].ResponseHeaderModifier),
		}

		if hRoutes[0].RequestRedirect != nil {
			route.Action = getRouteRedirect(hRoutes[0].RequestRedirect, listenerPort)
		} else {
			route.Action = getRouteAction(&r, backends, r.Rewrite, r.RequestMirrors)
		}
		routes = append(routes, &route)
		delete(matchBackendMap, r.GetMatchKey())
	}
	return routes
}

type routeActionMutation func(*envoy_config_route_v3.Route_Route) *envoy_config_route_v3.Route_Route

func hostRewriteMutation(rewrite *model.HTTPURLRewriteFilter) routeActionMutation {
	return func(route *envoy_config_route_v3.Route_Route) *envoy_config_route_v3.Route_Route {
		if rewrite == nil || rewrite.HostName == nil || route.Route == nil {
			return route
		}
		route.Route.HostRewriteSpecifier = &envoy_config_route_v3.RouteAction_HostRewriteLiteral{
			HostRewriteLiteral: *rewrite.HostName,
		}
		return route
	}
}

func pathPrefixMutation(rewrite *model.HTTPURLRewriteFilter, httpRoute *model.HTTPRoute) routeActionMutation {
	return func(route *envoy_config_route_v3.Route_Route) *envoy_config_route_v3.Route_Route {
		if rewrite == nil || rewrite.Path == nil || httpRoute == nil || len(rewrite.Path.Exact) != 0 || len(rewrite.Path.Regex) != 0 {
			return route
		}

		// Refer to: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io%2fv1beta1.HTTPPathModifier
		// ReplacePrefix is allowed to be empty.
		if len(rewrite.Path.Prefix) == 0 || rewrite.Path.Prefix == "/" {

			route.Route.RegexRewrite = &envoy_type_matcher_v3.RegexMatchAndSubstitute{
				Pattern: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^" + httpRoute.PathMatch.Prefix,
				},
				Substitution: "",
			}

		} else {
			route.Route.PrefixRewrite = rewrite.Path.Prefix
		}
		return route
	}
}

func pathFullReplaceMutation(rewrite *model.HTTPURLRewriteFilter) routeActionMutation {
	return func(route *envoy_config_route_v3.Route_Route) *envoy_config_route_v3.Route_Route {
		if rewrite == nil || rewrite.Path == nil || len(rewrite.Path.Exact) == 0 {
			return route
		}
		route.Route.RegexRewrite = &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				Regex: "^/.*$",
			},
			Substitution: rewrite.Path.Exact,
		}
		return route
	}
}

func requestMirrorMutation(mirrors []*model.HTTPRequestMirror) routeActionMutation {
	return func(route *envoy_config_route_v3.Route_Route) *envoy_config_route_v3.Route_Route {
		if len(mirrors) == 0 {
			return route
		}
		var action []*envoy_config_route_v3.RouteAction_RequestMirrorPolicy
		for _, m := range mirrors {
			if m.Backend == nil {
				continue
			}
			action = append(action, &envoy_config_route_v3.RouteAction_RequestMirrorPolicy{
				Cluster: fmt.Sprintf("%s/%s:%s", m.Backend.Namespace, m.Backend.Name, m.Backend.Port.GetPort()),
			})
		}
		route.Route.RequestMirrorPolicies = action
		return route
	}
}

func getRouteAction(route *model.HTTPRoute, backends []model.Backend, rewrite *model.HTTPURLRewriteFilter, mirrors []*model.HTTPRequestMirror) *envoy_config_route_v3.Route_Route {
	var routeAction *envoy_config_route_v3.Route_Route

	var mutators = []routeActionMutation{
		hostRewriteMutation(rewrite),
		pathPrefixMutation(rewrite, route),
		pathFullReplaceMutation(rewrite),
		requestMirrorMutation(mirrors),
	}

	if len(backends) == 1 {
		r := &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: fmt.Sprintf("%s/%s:%s", backends[0].Namespace, backends[0].Name, backends[0].Port.GetPort()),
				},
			},
		}

		for _, mutator := range mutators {
			r = mutator(r)
		}
		return r
	}

	weightedClusters := make([]*envoy_config_route_v3.WeightedCluster_ClusterWeight, 0, len(backends))
	for _, be := range backends {
		var weight int32 = 1
		if be.Weight != nil {
			weight = *be.Weight
		}
		weightedClusters = append(weightedClusters, &envoy_config_route_v3.WeightedCluster_ClusterWeight{
			Name:   fmt.Sprintf("%s/%s:%s", be.Namespace, be.Name, be.Port.GetPort()),
			Weight: wrapperspb.UInt32(uint32(weight)),
		})
	}
	routeAction = &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_WeightedClusters{
				WeightedClusters: &envoy_config_route_v3.WeightedCluster{
					Clusters: weightedClusters,
				},
			},
		},
	}
	for _, mutator := range mutators {
		routeAction = mutator(routeAction)
	}
	return routeAction
}

func getRouteRedirect(redirect *model.HTTPRequestRedirectFilter, listenerPort uint32) *envoy_config_route_v3.Route_Redirect {
	redirectAction := &envoy_config_route_v3.RedirectAction{}

	if redirect.Scheme != nil {
		redirectAction.SchemeRewriteSpecifier = &envoy_config_route_v3.RedirectAction_SchemeRedirect{
			SchemeRedirect: *redirect.Scheme,
		}
	}

	if redirect.Hostname != nil {
		redirectAction.HostRedirect = *redirect.Hostname
	}

	if redirect.Port != nil {
		redirectAction.PortRedirect = uint32(*redirect.Port)
	} else {
		if redirect.Scheme != nil {
			if *redirect.Scheme == "https" {
				redirectAction.PortRedirect = 443
			} else if *redirect.Scheme == "http" {
				redirectAction.PortRedirect = 80
			}
		} else {
			redirectAction.PortRedirect = listenerPort
		}
	}

	if redirect.StatusCode != nil {
		redirectAction.ResponseCode = toRedirectResponseCode(*redirect.StatusCode)
	}

	if redirect.Path != nil {
		if len(redirect.Path.Prefix) != 0 {
			redirectAction.PathRewriteSpecifier = &envoy_config_route_v3.RedirectAction_PrefixRewrite{
				PrefixRewrite: redirect.Path.Prefix,
			}
		}
		if len(redirect.Path.Exact) != 0 {
			redirectAction.PathRewriteSpecifier = &envoy_config_route_v3.RedirectAction_PathRedirect{
				PathRedirect: redirect.Path.Exact,
			}
		}
	}

	return &envoy_config_route_v3.Route_Redirect{
		Redirect: redirectAction,
	}
}

func envoyHTTPRouteNoBackend(route model.HTTPRoute, hostnames []string, hostNameSuffixMatch bool) *envoy_config_route_v3.Route {
	if route.DirectResponse == nil {
		return nil
	}

	return &envoy_config_route_v3.Route{
		Match: getRouteMatch(hostnames,
			hostNameSuffixMatch,
			route.PathMatch,
			route.HeadersMatch,
			route.QueryParamsMatch,
			route.Method),
		Action: &envoy_config_route_v3.Route_DirectResponse{
			DirectResponse: &envoy_config_route_v3.DirectResponseAction{
				Status: uint32(route.DirectResponse.StatusCode),
				Body: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineString{
						InlineString: route.DirectResponse.Body,
					},
				},
			},
		},
	}
}

func getRouteMatch(hostnames []string, hostNameSuffixMatch bool, pathMatch model.StringMatch, headers []model.KeyValueMatch, query []model.KeyValueMatch, method *string) *envoy_config_route_v3.RouteMatch {
	headerMatchers := getHeaderMatchers(hostnames, hostNameSuffixMatch, headers, method)
	queryMatchers := getQueryMatchers(query)

	switch {
	case pathMatch.Exact != "":
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: pathMatch.Exact,
			},
			Headers:         headerMatchers,
			QueryParameters: queryMatchers,
		}
	case pathMatch.Prefix == "/":
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: pathMatch.Prefix,
			},
			Headers:         headerMatchers,
			QueryParameters: queryMatchers,
		}
	case pathMatch.Prefix != "":
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
				PathSeparatedPrefix: strings.TrimSuffix(pathMatch.Prefix, "/"),
			},
			Headers:         headerMatchers,
			QueryParameters: queryMatchers,
		}
	case pathMatch.Regex != "":
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					Regex: pathMatch.Regex,
				},
			},
			Headers:         headerMatchers,
			QueryParameters: queryMatchers,
		}
	default:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: "/",
			},
			Headers:         headerMatchers,
			QueryParameters: queryMatchers,
		}
	}
}

func getQueryMatchers(query []model.KeyValueMatch) []*envoy_config_route_v3.QueryParameterMatcher {
	res := make([]*envoy_config_route_v3.QueryParameterMatcher, 0, len(query))
	for _, q := range query {
		res = append(res, &envoy_config_route_v3.QueryParameterMatcher{
			Name: q.Key,
			QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_StringMatch{
				StringMatch: getEnvoyStringMatcher(q.Match),
			},
		})
	}
	return res
}

func getHeaderMatchers(hostnames []string, hostNameSuffixMatch bool, headers []model.KeyValueMatch, method *string) []*envoy_config_route_v3.HeaderMatcher {
	var result []*envoy_config_route_v3.HeaderMatcher

	if !hostNameSuffixMatch {
		for _, host := range hostnames {
			if len(host) != 0 && host != wildCard && strings.Contains(host, wildCard) {
				// Make sure that wildcard character only match one single dns domain.
				// For example, if host is *.foo.com, baz.bar.foo.com should not match
				result = append(result, &envoy_config_route_v3.HeaderMatcher{
					Name: envoyAuthority,
					HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
						StringMatch: &envoy_type_matcher_v3.StringMatcher{
							MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
								SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
									Regex: getMatchingHeaderRegex(host),
								},
							},
						},
					},
				})
			}
		}
	}

	for _, h := range headers {
		result = append(result, &envoy_config_route_v3.HeaderMatcher{
			Name: h.Key,
			HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
				StringMatch: getEnvoyStringMatcher(h.Match),
			},
		})
	}

	if method != nil {
		result = append(result, &envoy_config_route_v3.HeaderMatcher{
			Name: ":method",
			HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: strings.ToUpper(*method),
					},
				},
			},
		})
	}

	return result
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

func getEnvoyStringMatcher(s model.StringMatch) *envoy_type_matcher_v3.StringMatcher {
	if s.Exact != "" {
		return &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: s.Exact,
			},
		}
	}
	if s.Prefix != "" {
		return &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Prefix{
				Prefix: s.Prefix,
			},
		}
	}
	if s.Regex != "" {
		return &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					Regex: s.Regex,
				},
			},
		}
	}
	return nil
}

func getHeadersToAdd(filter *model.HTTPHeaderFilter) []*envoy_config_core_v3.HeaderValueOption {
	if filter == nil {
		return nil
	}
	result := make(
		[]*envoy_config_core_v3.HeaderValueOption,
		0,
		len(filter.HeadersToAdd)+len(filter.HeadersToSet),
	)
	for _, h := range filter.HeadersToAdd {
		result = append(result, &envoy_config_core_v3.HeaderValueOption{
			Header: &envoy_config_core_v3.HeaderValue{
				Key:   h.Name,
				Value: h.Value,
			},
			AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
		})
	}

	for _, h := range filter.HeadersToSet {
		result = append(result, &envoy_config_core_v3.HeaderValueOption{
			Header: &envoy_config_core_v3.HeaderValue{
				Key:   h.Name,
				Value: h.Value,
			},
			AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return result
}

func getHeadersToRemove(filter *model.HTTPHeaderFilter) []string {
	if filter == nil {
		return nil
	}
	return filter.HeadersToRemove
}

func toRedirectResponseCode(statusCode int) envoy_config_route_v3.RedirectAction_RedirectResponseCode {
	switch statusCode {
	case 301:
		return envoy_config_route_v3.RedirectAction_MOVED_PERMANENTLY
	case 302:
		return envoy_config_route_v3.RedirectAction_FOUND
	case 303:
		return envoy_config_route_v3.RedirectAction_SEE_OTHER
	case 307:
		return envoy_config_route_v3.RedirectAction_TEMPORARY_REDIRECT
	case 308:
		return envoy_config_route_v3.RedirectAction_PERMANENT_REDIRECT
	default:
		return envoy_config_route_v3.RedirectAction_MOVED_PERMANENTLY
	}
}
