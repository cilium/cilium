// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/pkg/model"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var exactPathType = slim_networkingv1.PathTypeExact

var prefixPathType = slim_networkingv1.PathTypePrefix

var testAnnotations = map[string]string{
	"service.beta.kubernetes.io/dummy-load-balancer-backend-protocol":    "http",
	"service.beta.kubernetes.io/dummy-load-balancer-access-log-enabled":  "true",
	"service.alpha.kubernetes.io/dummy-load-balancer-access-log-enabled": "true",
}

// Add the ingress objects in
// https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/features
// as test fixtures

// Just a default backend should produce one simple listener.
var defaultBackend = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:      "load-balancing",
		Namespace: "random-namespace",
	},
	Spec: slim_networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &slim_networkingv1.IngressBackend{
			Service: &slim_networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: slim_networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var defaultBackendLegacy = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "load-balancing",
		Namespace:   "random-namespace",
		Annotations: map[string]string{"kubernetes.io/ingress.class": "cilium"},
	},
	Spec: slim_networkingv1.IngressSpec{
		DefaultBackend: &slim_networkingv1.IngressBackend{
			Service: &slim_networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: slim_networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var defaultBackendLegacyOverride = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "load-balancing",
		Namespace:   "random-namespace",
		Annotations: map[string]string{"kubernetes.io/ingress.class": "cilium"},
	},
	Spec: slim_networkingv1.IngressSpec{
		IngressClassName: stringp("contour"),
		DefaultBackend: &slim_networkingv1.IngressBackend{
			Service: &slim_networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: slim_networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var defaultBackendListeners = []model.HTTPListener{
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
}

// Ingress Conformance test resources

// The hostRules resource from the ingress conformance test should produce
// three listeners, one for host with no TLS config, then one insecure and one
// secure for the host with TLS config.
var hostRules = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:      "host-rules",
		Namespace: "random-namespace",
	},
	Spec: slim_networkingv1.IngressSpec{
		TLS: []slim_networkingv1.IngressTLS{
			{
				Hosts:      []string{"foo.bar.com"},
				SecretName: "conformance-tls",
			},
		},
		Rules: []slim_networkingv1.IngressRule{
			{
				Host: "*.foo.com",
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "wildcard-foo-com",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
						},
					},
				},
			},
			{
				Host: "foo.bar.com",
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "foo-bar-com",
										Port: slim_networkingv1.ServiceBackendPort{
											Name: "http",
										},
									},
								},
								PathType: &prefixPathType,
							},
						},
					},
				},
			},
		},
	},
}

var hostRulesListeners = []model.HTTPListener{
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
}

// The pathRules resource should produce four listeners, one for each host
// used in the Ingress.

var pathRules = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:      "path-rules",
		Namespace: "random-namespace",
	},
	Spec: slim_networkingv1.IngressSpec{
		Rules: []slim_networkingv1.IngressRule{
			{
				Host: "exact-path-rules",
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/foo",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "foo-exact",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
						},
					},
				},
			},
			{
				Host: "prefix-path-rules",
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/foo",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "foo-prefix",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/aaa/bbb",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "aaa-slash-bbb-prefix",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/aaa",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "aaa-prefix",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
						},
					},
				},
			},
			{
				Host: "mixed-path-rules",
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/foo",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "foo-prefix",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/foo",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "foo-exact",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
						},
					},
				},
			},
			{
				Host: "trailing-slash-path-rules",
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/aaa/bbb/",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "aaa-slash-bbb-slash-prefix",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/foo/",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "foo-slash-exact",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
						},
					},
				},
			},
		},
	},
}

var pathRulesListeners = []model.HTTPListener{
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
}

// The complexIngress resource from the operator/pkg/ingress testsuite should
// produce three Listeners with identical routes, for the default host `*`,
// and then the two TLS hostnames.
var complexIngress = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "dummy-ingress",
		Namespace:   "dummy-namespace",
		Annotations: testAnnotations,
		UID:         "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	},
	Spec: slim_networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &slim_networkingv1.IngressBackend{
			Service: &slim_networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: slim_networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
		TLS: []slim_networkingv1.IngressTLS{
			{
				Hosts:      []string{"very-secure.server.com"},
				SecretName: "tls-very-secure-server-com",
			},
			{
				Hosts: []string{
					"another-very-secure.server.com",
					"not-in-use.another-very-secure.server.com",
				},
				SecretName: "tls-another-very-secure-server-com",
			},
		},
		Rules: []slim_networkingv1.IngressRule{
			{
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/dummy-path",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
							{
								Path: "/another-dummy-path",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "another-dummy-backend",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8081,
										},
									},
								},
								PathType: &prefixPathType,
							},
						},
					},
				},
			},
		},
	},
}

var complexIngressListeners = []model.HTTPListener{
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
				UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
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
				UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
			},
		},
		Port:     443,
		Hostname: "not-in-use.another-very-secure.server.com",
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
				UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
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
}

// complexNodePortIngress is same as complexIngress but with NodePort service
var complexNodePortIngress = slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/service-type":       "NodePort",
			"ingress.cilium.io/insecure-node-port": "30000",
			"ingress.cilium.io/secure-node-port":   "30001",
		},
		UID: "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	},
	Spec: slim_networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &slim_networkingv1.IngressBackend{
			Service: &slim_networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: slim_networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
		TLS: []slim_networkingv1.IngressTLS{
			{
				Hosts:      []string{"very-secure.server.com"},
				SecretName: "tls-very-secure-server-com",
			},
			{
				Hosts: []string{
					"another-very-secure.server.com",
					"not-in-use.another-very-secure.server.com",
				},
				SecretName: "tls-another-very-secure-server-com",
			},
		},
		Rules: []slim_networkingv1.IngressRule{
			{
				IngressRuleValue: slim_networkingv1.IngressRuleValue{
					HTTP: &slim_networkingv1.HTTPIngressRuleValue{
						Paths: []slim_networkingv1.HTTPIngressPath{
							{
								Path: "/dummy-path",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
							{
								Path: "/another-dummy-path",
								Backend: slim_networkingv1.IngressBackend{
									Service: &slim_networkingv1.IngressServiceBackend{
										Name: "another-dummy-backend",
										Port: slim_networkingv1.ServiceBackendPort{
											Number: 8081,
										},
									},
								},
								PathType: &prefixPathType,
							},
						},
					},
				},
			},
		},
	},
}

var complexNodePortIngressListeners = []model.HTTPListener{
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
		Service: &model.Service{
			Type:             "NodePort",
			InsecureNodePort: uint32p(30000),
			SecureNodePort:   uint32p(30001),
		},
	},
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
		Service: &model.Service{
			Type:             "NodePort",
			InsecureNodePort: uint32p(30000),
			SecureNodePort:   uint32p(30001),
		},
	},
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
		Port:     443,
		Hostname: "not-in-use.another-very-secure.server.com",
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
		Service: &model.Service{
			Type:             "NodePort",
			InsecureNodePort: uint32p(30000),
			SecureNodePort:   uint32p(30001),
		},
	},
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
		Service: &model.Service{
			Type:             "NodePort",
			InsecureNodePort: uint32p(30000),
			SecureNodePort:   uint32p(30001),
		},
	},
}

func stringp(in string) *string {
	return &in
}

func uint32p(in uint32) *uint32 {
	return &in
}

type testcase struct {
	ingress slim_networkingv1.Ingress
	want    []model.HTTPListener
}

func TestIngress(t *testing.T) {

	tests := map[string]testcase{
		"conformance default backend test": {
			ingress: defaultBackend,
			want:    defaultBackendListeners,
		},
		"conformance default backend (legacy annotation) test": {
			ingress: defaultBackendLegacy,
			want:    defaultBackendListeners,
		},
		"conformance default backend (legacy + new) test": {
			ingress: defaultBackendLegacyOverride,
			want:    defaultBackendListeners,
		},
		"conformance host rules test": {
			ingress: hostRules,
			want:    hostRulesListeners,
		},
		"conformance path rules test": {
			ingress: pathRules,
			want:    pathRulesListeners,
		},
		"cilium test ingress": {
			ingress: complexIngress,
			want:    complexIngressListeners,
		},
		"cilium test ingress with NodePort": {
			ingress: complexNodePortIngress,
			want:    complexNodePortIngressListeners,
		},
	}

	for name, tc := range tests {

		t.Run(name, func(t *testing.T) {
			listeners := Ingress(tc.ingress)
			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}
