// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"

	"github.com/cilium/cilium/operator/pkg/model"
)

// This file contains text fixtures and expected configs for the
// TestSharedIngressTranslator_getEnvoyHTTPRouteConfiguration test.
//
// The format is a model.Model representing the input, and a
// []*envoy_config_route_v3.RouteConfiguration representing the output.
//
// NOTE: For models that have some TLS config - anything with an insecure *and*
// secure listener in the resultant RouteConfiguration, you _must_ make sure
// you test with enforceHTTPS true and false.

// Some of these test fixtures are coming from Conformance Suite for Ingress API.
// https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/features

var defaultBackendModel = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "load-balancing",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
	},
}

var defaultBackendExpectedConfig = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "*",
				Domains: domainsHelper("*"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("random-namespace", "default-backend", "8080"),
					},
				},
			},
		},
	},
}

var hostRulesModel = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Name: "ing-host-rules-random-namespace-*.foo.com",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "host-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "*.foo.com",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "wildcard-foo-com",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-host-rules-random-namespace-foo.bar.com",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "host-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "foo.bar.com",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-bar-com",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Name: "http",
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-host-rules-random-namespace-foo.bar.com",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "host-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     443,
			Hostname: "foo.bar.com",
			TLS: []model.TLSSecret{
				{
					Name:      "conformance-tls",
					Namespace: "random-namespace",
				},
			},
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-bar-com",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Name: "http",
							},
						},
					},
				},
			},
		},
	},
}

var hostRulesExpectedConfig = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "*.foo.com",
				Domains: domainsHelper("*.foo.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  withAuthority(envoyRouteMatchRootPath(), "^[^.]+[.]foo[.]com$"),
						Action: envoyRouteAction("random-namespace", "wildcard-foo-com", "8080"),
					},
				},
			},
			{
				Name:    "foo.bar.com",
				Domains: domainsHelper("foo.bar.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("random-namespace", "foo-bar-com", "http"),
					},
				},
			},
		},
	},
	{
		Name: "listener-secure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "foo.bar.com",
				Domains: domainsHelper("foo.bar.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("random-namespace", "foo-bar-com", "http"),
					},
				},
			},
		},
	},
}

var hostRulesModelEnforcedHTTPS = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Name: "ing-host-rules-random-namespace-*.foo.com",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "host-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "*.foo.com",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "wildcard-foo-com",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-host-rules-random-namespace-foo.bar.com",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "host-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "foo.bar.com",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-bar-com",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Name: "http",
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-host-rules-random-namespace-foo.bar.com",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "host-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     443,
			Hostname: "foo.bar.com",
			TLS: []model.TLSSecret{
				{
					Name:      "conformance-tls",
					Namespace: "random-namespace",
				},
			},
			ForceHTTPtoHTTPSRedirect: true,
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-bar-com",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Name: "http",
							},
						},
					},
				},
			},
		},
	},
}

var hostRulesExpectedConfigEnforceHTTPS = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "*.foo.com",
				Domains: domainsHelper("*.foo.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  withAuthority(envoyRouteMatchRootPath(), "^[^.]+[.]foo[.]com$"),
						Action: envoyRouteAction("random-namespace", "wildcard-foo-com", "8080"),
					},
				},
			},
			{
				Name:    "foo.bar.com",
				Domains: domainsHelper("foo.bar.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyHTTPSRouteRedirect(),
					},
				},
			},
		},
	},
	{
		Name: "listener-secure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "foo.bar.com",
				Domains: domainsHelper("foo.bar.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("random-namespace", "foo-bar-com", "http"),
					},
				},
			},
		},
	},
}

var pathRulesModel = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Name: "ing-path-rules-random-namespace-exact-path-rules",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "path-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "exact-path-rules",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Exact: "/foo",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-exact",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-path-rules-random-namespace-mixed-path-rules",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "path-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "mixed-path-rules",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/foo",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-prefix",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/foo",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-exact",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-path-rules-random-namespace-prefix-path-rules",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "path-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "prefix-path-rules",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/foo",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-prefix",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/aaa/bbb",
					},
					Backends: []model.Backend{
						{
							Name:      "aaa-slash-bbb-prefix",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/aaa",
					},
					Backends: []model.Backend{
						{
							Name:      "aaa-prefix",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
		{
			Name: "ing-path-rules-random-namespace-trailing-slash-path-rules",
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "path-rules",
					Namespace: "random-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "trailing-slash-path-rules",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Prefix: "/aaa/bbb/",
					},
					Backends: []model.Backend{
						{
							Name:      "aaa-slash-bbb-slash-prefix",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/foo/",
					},
					Backends: []model.Backend{
						{
							Name:      "foo-slash-exact",
							Namespace: "random-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
			},
		},
	},
}

var pathRulesExpectedConfig = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "exact-path-rules",
				Domains: domainsHelper("exact-path-rules"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/foo"),
						Action: envoyRouteAction("random-namespace", "foo-exact", "8080"),
					},
				},
			},
			{
				Name:    "mixed-path-rules",
				Domains: domainsHelper("mixed-path-rules"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/foo"),
						Action: envoyRouteAction("random-namespace", "foo-exact", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/foo"),
						Action: envoyRouteAction("random-namespace", "foo-prefix", "8080"),
					},
				},
			},
			{
				Name:    "prefix-path-rules",
				Domains: domainsHelper("prefix-path-rules"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchPrefixPath("/aaa/bbb"),
						Action: envoyRouteAction("random-namespace", "aaa-slash-bbb-prefix", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/foo"),
						Action: envoyRouteAction("random-namespace", "foo-prefix", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/aaa"),
						Action: envoyRouteAction("random-namespace", "aaa-prefix", "8080"),
					},
				},
			},
			{
				Name:    "trailing-slash-path-rules",
				Domains: domainsHelper("trailing-slash-path-rules"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/foo/"),
						Action: envoyRouteAction("random-namespace", "foo-slash-exact", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/aaa/bbb"),
						Action: envoyRouteAction("random-namespace", "aaa-slash-bbb-slash-prefix", "8080"),
					},
				},
			},
		},
	},
}

var complexIngressModel = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/another-dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     443,
			Hostname: "another-very-secure.server.com",
			TLS: []model.TLSSecret{
				{
					Name:      "tls-another-very-secure-server-com",
					Namespace: "dummy-namespace",
				},
			},
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/another-dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     443,
			Hostname: "very-secure.server.com",
			TLS: []model.TLSSecret{
				{
					Name:      "tls-very-secure-server-com",
					Namespace: "dummy-namespace",
				},
			},
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/another-dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
	},
}

var complexIngressModelwithRedirects = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     80,
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/another-dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     443,
			Hostname: "another-very-secure.server.com",
			TLS: []model.TLSSecret{
				{
					Name:      "tls-another-very-secure-server-com",
					Namespace: "dummy-namespace",
				},
			},
			ForceHTTPtoHTTPSRedirect: true,
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/another-dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
				},
			},
			Port:     443,
			Hostname: "very-secure.server.com",
			TLS: []model.TLSSecret{
				{
					Name:      "tls-very-secure-server-com",
					Namespace: "dummy-namespace",
				},
			},
			ForceHTTPtoHTTPSRedirect: true,
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						{
							Name:      "default-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/another-dummy-path",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
	},
}

var complexIngressExpectedConfig = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "*",
				Domains: domainsHelper("*"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "default-backend", "8080"),
					},
				},
			},
		},
	},
	{
		Name: "listener-secure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "another-very-secure.server.com",
				Domains: domainsHelper("another-very-secure.server.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "default-backend", "8080"),
					},
				},
			},
			{
				Name:    "very-secure.server.com",
				Domains: domainsHelper("very-secure.server.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "default-backend", "8080"),
					},
				},
			},
		},
	},
}

var complexIngressExpectedConfigEnforceHTTPS = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "*",
				Domains: domainsHelper("*"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "default-backend", "8080"),
					},
				},
			},
			{
				Name:    "another-very-secure.server.com",
				Domains: domainsHelper("another-very-secure.server.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyHTTPSRouteRedirect(),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyHTTPSRouteRedirect(),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyHTTPSRouteRedirect(),
					},
				},
			},
			{
				Name:    "very-secure.server.com",
				Domains: domainsHelper("very-secure.server.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyHTTPSRouteRedirect(),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyHTTPSRouteRedirect(),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyHTTPSRouteRedirect(),
					},
				},
			},
		},
	},
	{
		Name: "listener-secure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "another-very-secure.server.com",
				Domains: domainsHelper("another-very-secure.server.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "default-backend", "8080"),
					},
				},
			},
			{
				Name:    "very-secure.server.com",
				Domains: domainsHelper("very-secure.server.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchPrefixPath("/another-dummy-path"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "default-backend", "8080"),
					},
				},
			},
		},
	},
}

// multiplePathTypesModel is used to test that sorting of different path
// types works correctly.
//
// It's based off of the output of the multiplePathTypes Ingress check in
// operator/pkg/model/ingestion/ingress_test.go.
var multiplePathTypesModel = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
					UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
				},
			},
			Port:     80,
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					PathMatch: model.StringMatch{
						Regex: "/impl",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Prefix: "/",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
				{
					PathMatch: model.StringMatch{
						Exact: "/exact",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
	},
}

var multiplePathTypesExpectedConfig = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "*",
				Domains: domainsHelper("*"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchExactPath("/exact"),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
					{
						Match:  envoyRouteMatchImplementationSpecific("/impl"),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
				},
			},
		},
	},
}

// multiplePathTypesModel is used to test that sorting of different path
// types works correctly.
//
// It's based off of the output of the multiplePathTypes Ingress check in
// operator/pkg/model/ingestion/ingress_test.go.
var multipleRouteHostnamesModel = &model.Model{
	HTTP: []model.HTTPListener{
		{
			Sources: []model.FullyQualifiedResource{
				{
					Name:      "dummy-ingress",
					Namespace: "dummy-namespace",
					Version:   "v1",
					Kind:      "Ingress",
					UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
				},
			},
			Port:     80,
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					Hostnames: []string{
						"foo.example.com",
						"bar.example.com",
					},
					Backends: []model.Backend{
						{
							Name:      "dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8080,
							},
						},
					},
				},
				{
					Hostnames: []string{
						"baz.example.com",
						"quux.example.com",
					},
					Backends: []model.Backend{
						{
							Name:      "another-dummy-backend",
							Namespace: "dummy-namespace",
							Port: &model.BackendPort{
								Port: 8081,
							},
						},
					},
				},
			},
		},
	},
}

var multipleRouteHostnamesExpectedConfig = []*envoy_config_route_v3.RouteConfiguration{
	{
		Name: "listener-insecure",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{
			{
				Name:    "bar.example.com",
				Domains: domainsHelper("bar.example.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
				},
			},
			{
				Name:    "baz.example.com",
				Domains: domainsHelper("baz.example.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
				},
			},
			{
				Name:    "foo.example.com",
				Domains: domainsHelper("foo.example.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "dummy-backend", "8080"),
					},
				},
			},
			{
				Name:    "quux.example.com",
				Domains: domainsHelper("quux.example.com"),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match:  envoyRouteMatchRootPath(),
						Action: envoyRouteAction("dummy-namespace", "another-dummy-backend", "8081"),
					},
				},
			},
		},
	},
}
