// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import "github.com/cilium/cilium/operator/pkg/model"

// The test fixtures are coming from Conformance Suite for Ingress API.
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
