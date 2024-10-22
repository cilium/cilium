// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
)

var exactPathType = networkingv1.PathTypeExact

var prefixPathType = networkingv1.PathTypePrefix

var implementationSpecificPathType = networkingv1.PathTypeImplementationSpecific

var testAnnotations = map[string]string{
	"service.beta.kubernetes.io/dummy-load-balancer-backend-protocol":    "http",
	"service.beta.kubernetes.io/dummy-load-balancer-access-log-enabled":  "true",
	"service.alpha.kubernetes.io/dummy-load-balancer-access-log-enabled": "true",
}

var defaultSecretNamespace = "default-secret-namespace"

var defaultSecretName = "default-secret-name"

// Add the ingress objects in
// https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/features
// as test fixtures

// default timeout for the ingress conformance tests
var listenerDefaultTimeout = model.Timeout{
	Request: nil,
}

// Just a default backend should produce one simple listener.
var defaultBackend = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "load-balancing",
		Namespace: "random-namespace",
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var defaultBackendLegacy = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:        "load-balancing",
		Namespace:   "random-namespace",
		Annotations: map[string]string{"kubernetes.io/ingress.class": "cilium"},
	},
	Spec: networkingv1.IngressSpec{
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var defaultBackendLegacyOverride = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:        "load-balancing",
		Namespace:   "random-namespace",
		Annotations: map[string]string{"kubernetes.io/ingress.class": "cilium"},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("contour"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

var defaultBackendListenersWithRequestTimeout = []model.HTTPListener{
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
				Timeout: model.Timeout{
					Request: ptr.To(time.Second * 10),
				},
			},
		},
	},
}

// Ingress Conformance test resources

// The hostRules resource from the ingress conformance test should produce
// three listeners, one for host with no TLS config, then one insecure and one
// secure for the host with TLS config.
var hostRules = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "host-rules",
		Namespace: "random-namespace",
	},
	Spec: networkingv1.IngressSpec{
		TLS: []networkingv1.IngressTLS{
			{
				Hosts:      []string{"foo.bar.com"},
				SecretName: "conformance-tls",
			},
		},
		Rules: []networkingv1.IngressRule{
			{
				Host: "*.foo.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "wildcard-foo-com",
										Port: networkingv1.ServiceBackendPort{
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
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-bar-com",
										Port: networkingv1.ServiceBackendPort{
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

// The pathRules resource should produce four listeners, one for each host
// used in the Ingress.

var pathRules = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "path-rules",
		Namespace: "random-namespace",
	},
	Spec: networkingv1.IngressSpec{
		Rules: []networkingv1.IngressRule{
			{
				Host: "exact-path-rules",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/foo",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-exact",
										Port: networkingv1.ServiceBackendPort{
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
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/foo",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-prefix",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/aaa/bbb",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "aaa-slash-bbb-prefix",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/aaa",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "aaa-prefix",
										Port: networkingv1.ServiceBackendPort{
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
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/foo",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-prefix",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/foo",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-exact",
										Port: networkingv1.ServiceBackendPort{
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
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/aaa/bbb/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "aaa-slash-bbb-slash-prefix",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/foo/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-slash-exact",
										Port: networkingv1.ServiceBackendPort{
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

// The complexIngress resource from the operator/pkg/ingress testsuite should
// produce three Listeners with identical routes, for the default host `*`,
// and then the two TLS hostnames.
var complexIngress = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:        "dummy-ingress",
		Namespace:   "dummy-namespace",
		Annotations: testAnnotations,
		Labels:      testAnnotations,
		UID:         "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
		TLS: []networkingv1.IngressTLS{
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
		Rules: []networkingv1.IngressRule{
			{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/dummy-path",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
							{
								Path: "/another-dummy-path",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "another-dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

// complexNodePortIngress is same as complexIngress but with NodePort service
var complexNodePortIngress = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/service-type":       "NodePort",
			"ingress.cilium.io/insecure-node-port": "30000",
			"ingress.cilium.io/secure-node-port":   "30001",
		},
		UID: "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
		TLS: []networkingv1.IngressTLS{
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
		Rules: []networkingv1.IngressRule{
			{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/dummy-path",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
							{
								Path: "/another-dummy-path",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "another-dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
			},
		},
		Service: &model.Service{
			Type:             "NodePort",
			InsecureNodePort: uint32p(30000),
			SecureNodePort:   uint32p(30001),
		},
	},
}

// multiplePathTypes checks what happens when we have multiple path types in
// the one Ingress object.
//
// Note that there's no sorting done at this point, the sorting is performed
// in the translation step, not this ingestion step.
var multiplePathTypes = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/impl",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &implementationSpecificPathType,
							},
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "another-dummy-backend",
										Port: networkingv1.ServiceBackendPort{
											Number: 8081,
										},
									},
								},
								PathType: &prefixPathType,
							},
							{
								Path: "/exact",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "another-dummy-backend",
										Port: networkingv1.ServiceBackendPort{
											Number: 8081,
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

var multiplePathTypesListeners = []model.HTTPListener{
	{
		Name: "ing-dummy-ingress-dummy-namespace-*",
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

// hostRulesForceHTTPSenabled tests the force-https annotation and should produce
// three listeners, one for host with no TLS config, then one insecure and one
// secure for the host with TLS config.
var hostRulesForceHTTPSenabled = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "host-rules",
		Namespace: "random-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/force-https": "enabled",
		},
	},
	Spec: networkingv1.IngressSpec{
		TLS: []networkingv1.IngressTLS{
			{
				Hosts:      []string{"foo.bar.com"},
				SecretName: "conformance-tls",
			},
		},
		Rules: []networkingv1.IngressRule{
			{
				Host: "*.foo.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "wildcard-foo-com",
										Port: networkingv1.ServiceBackendPort{
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
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-bar-com",
										Port: networkingv1.ServiceBackendPort{
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

var hostRulesForceHTTPSenabledListeners = []model.HTTPListener{
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

// forceHTTPSenabled tests the force-https annotation and should produce
// three listeners, one for host with no TLS config, then one insecure and one
// secure for the host with TLS config.
var hostRulesForceHTTPSdisabled = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "host-rules",
		Namespace: "random-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/force-https": "disabled",
		},
	},
	Spec: networkingv1.IngressSpec{
		TLS: []networkingv1.IngressTLS{
			{
				Hosts:      []string{"foo.bar.com"},
				SecretName: "conformance-tls",
			},
		},
		Rules: []networkingv1.IngressRule{
			{
				Host: "*.foo.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "wildcard-foo-com",
										Port: networkingv1.ServiceBackendPort{
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
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "foo-bar-com",
										Port: networkingv1.ServiceBackendPort{
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

var requestTimeoutAnnotationIngress = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "load-balancing-request-timeout-annotation",
		Namespace: "random-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/request-timeout": "10s",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var requestTimeoutAnnotationListeners = []model.HTTPListener{
	{
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "load-balancing-request-timeout-annotation",
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
				Timeout: model.Timeout{
					Request: ptr.To(time.Second * 10),
				},
			},
		},
	},
}

var requestTimeoutInvalidIngress = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "load-balancing-request-timeout-invalid-annotation",
		Namespace: "random-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/request-timeout": "invalid-duration",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
	},
}

var requestTimeoutInvalidListeners = []model.HTTPListener{
	{
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "load-balancing-request-timeout-invalid-annotation",
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
				Timeout: listenerDefaultTimeout,
			},
		},
	},
}

func stringp(in string) *string {
	return &in
}

func uint32p(in uint32) *uint32 {
	return &in
}

func removeIngressTLSsecretName(ing networkingv1.Ingress) networkingv1.Ingress {
	ret := networkingv1.Ingress{}
	ing.DeepCopyInto(&ret)
	for i := range ret.Spec.TLS {
		ret.Spec.TLS[i].SecretName = ""
	}
	return ret
}

func removeListenersTLSsecret(listeners []model.HTTPListener) []model.HTTPListener {
	ret := []model.HTTPListener{}
	for _, listener := range listeners {
		listener.TLS = nil
		ret = append(ret, listener)
	}
	return ret
}

func useDefaultListenersTLSsecret(listeners []model.HTTPListener) []model.HTTPListener {
	ret := []model.HTTPListener{}
	for _, listener := range listeners {
		if listener.Port == 443 {
			listener.TLS = []model.TLSSecret{
				{Namespace: defaultSecretNamespace, Name: defaultSecretName},
			}
		}
		ret = append(ret, listener)
	}
	return ret
}

func removeIngressHTTPRuleValues(ing networkingv1.Ingress) networkingv1.Ingress {
	var rules []networkingv1.IngressRule

	for _, r := range ing.Spec.Rules {
		r.HTTP = nil
		rules = append(rules, r)
	}

	ret := networkingv1.Ingress{}
	ing.DeepCopyInto(&ret)
	ret.Spec.Rules = rules

	return ret
}

type testcase struct {
	ingress        networkingv1.Ingress
	defaultSecret  bool
	enforceHTTPS   bool
	requestTimeout time.Duration
	want           []model.HTTPListener
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
		"cilium test ingress without http rules": {
			ingress: removeIngressHTTPRuleValues(hostRules),
			want:    []model.HTTPListener{},
		},
		"conformance host rules test": {
			ingress: hostRules,
			want:    hostRulesListeners,
		},
		"conformance host rules test without SecretName": {
			ingress: removeIngressTLSsecretName(hostRules),
			want:    removeListenersTLSsecret(hostRulesListeners),
		},
		"conformance path rules test": {
			ingress: pathRules,
			want:    pathRulesListeners,
		},
		"cilium test ingress": {
			ingress: complexIngress,
			want:    complexIngressListeners,
		},
		"cilium test ingress without SecretName": {
			ingress: removeIngressTLSsecretName(complexIngress),
			want:    removeListenersTLSsecret(complexIngressListeners),
		},
		"cilium test ingress with NodePort": {
			ingress: complexNodePortIngress,
			want:    complexNodePortIngressListeners,
		},
		"cilium test ingress with NodePort without SecretName": {
			ingress: removeIngressTLSsecretName(complexNodePortIngress),
			want:    removeListenersTLSsecret(complexNodePortIngressListeners),
		},
		"conformance default backend test with default secret": {
			ingress:       defaultBackend,
			defaultSecret: true,
			want:          defaultBackendListeners,
		},
		"conformance default backend (legacy annotation) test with default secret": {
			ingress:       defaultBackendLegacy,
			defaultSecret: true,
			want:          defaultBackendListeners,
		},
		"conformance default backend (legacy + new) test with default secret": {
			ingress:       defaultBackendLegacyOverride,
			defaultSecret: true,
			want:          defaultBackendListeners,
		},
		"conformance host rules test with default secret": {
			ingress:       hostRules,
			defaultSecret: true,
			want:          hostRulesListeners,
		},
		"conformance host rules test with default secret without SecretName": {
			ingress:       removeIngressTLSsecretName(hostRules),
			defaultSecret: true,
			want:          useDefaultListenersTLSsecret(hostRulesListeners),
		},
		"conformance path rules test with default secret": {
			ingress:       pathRules,
			defaultSecret: true,
			want:          pathRulesListeners,
		},
		"cilium test ingress with default secret": {
			ingress:       complexIngress,
			defaultSecret: true,
			want:          complexIngressListeners,
		},
		"cilium test ingress with default secret without SecretName": {
			ingress:       removeIngressTLSsecretName(complexIngress),
			defaultSecret: true,
			want:          useDefaultListenersTLSsecret(complexIngressListeners),
		},
		"cilium test ingress with NodePort with default secret": {
			ingress:       complexNodePortIngress,
			defaultSecret: true,
			want:          complexNodePortIngressListeners,
		},
		"cilium test ingress with NodePort with default secret without SecretName": {
			ingress:       removeIngressTLSsecretName(complexNodePortIngress),
			defaultSecret: true,
			want:          useDefaultListenersTLSsecret(complexNodePortIngressListeners),
		},
		"cilium multiple path types": {
			ingress: multiplePathTypes,
			want:    multiplePathTypesListeners,
		},
		"force-https annotation present and enabled": {
			ingress: hostRulesForceHTTPSenabled,
			want:    hostRulesForceHTTPSenabledListeners,
		},
		"force-https annotation present and enabled, enforceHTTPS enabled": {
			ingress:      hostRulesForceHTTPSenabled,
			want:         hostRulesForceHTTPSenabledListeners,
			enforceHTTPS: true,
		},
		"force-https annotation present and disabled, enforceHTTPS enabled": {
			ingress:      hostRulesForceHTTPSdisabled,
			want:         hostRulesListeners,
			enforceHTTPS: true,
		},
		"force-https annotation present and disabled, enforceHTTPS disabled": {
			ingress: hostRulesForceHTTPSdisabled,
			want:    hostRulesListeners,
		},
		"force-https annotation not present, enforceHTTPS enabled": {
			ingress:      hostRules,
			want:         hostRulesForceHTTPSenabledListeners,
			enforceHTTPS: true,
		},
		"request-timeout flag present with no annotation": {
			ingress:        defaultBackend,
			want:           defaultBackendListenersWithRequestTimeout,
			requestTimeout: time.Second * 10,
		},
		"request-timeout annotation present": {
			ingress: requestTimeoutAnnotationIngress,
			want:    requestTimeoutAnnotationListeners,
		},
		"request-timeout annotation present but invalid": {
			ingress: requestTimeoutInvalidIngress,
			want:    requestTimeoutInvalidListeners,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var listeners []model.HTTPListener
			if tc.defaultSecret {
				listeners = Ingress(tc.ingress, defaultSecretNamespace, defaultSecretName, tc.enforceHTTPS, 80, 443, tc.requestTimeout)
			} else {
				listeners = Ingress(tc.ingress, "", "", tc.enforceHTTPS, 80, 443, tc.requestTimeout)
			}

			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}

// SSL Passthrough tests
//
// Sources for the SSL Passthrough Ingress objects
var sslPassthruSources = []model.FullyQualifiedResource{
	{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Version:   "v1",
		Kind:      "Ingress",
	},
}

var emptyTLSListeners = []model.TLSPassthroughListener{}

// sslPassthru tests basic SSL Passthrough
var sslPassthru = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/tls-passthrough": "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				Host: "sslpassthru.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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

var sslPassthruTLSListeners = []model.TLSPassthroughListener{
	{
		Name:     "ing-sslpassthru-ingress-dummy-namespace-sslpassthru.example.com",
		Sources:  sslPassthruSources,
		Port:     443,
		Hostname: "sslpassthru.example.com",
		Routes: []model.TLSPassthroughRoute{
			{
				Hostnames: []string{
					"sslpassthru.example.com",
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
		},
	},
}

// sslPassthruNoHost tests when there's no host set
var sslPassthruNoHost = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/tls-passthrough": "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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

// sslPassthruNoRule tests when there's a hostname but no rule at all
var sslPassthruNoRule = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/tls-passthrough": "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				Host:             "sslpassthru.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{},
			},
		},
	},
}

// sslPassthruExtraPath tests when a hostname and a rule but the path isn't '/'
var sslPassthruExtraPath = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/tls-passthrough": "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				Host: "sslpassthru.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/prefix",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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

// sslPassthruNodePort tests when the Ingress has a NodePort Service set.
var sslPassthruNodePort = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/service-type":       "NodePort",
			"ingress.cilium.io/insecure-node-port": "30000",
			"ingress.cilium.io/secure-node-port":   "30001",
			"ingress.cilium.io/tls-passthrough":    "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				Host: "sslpassthru.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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

var sslPassthruTLSListenersNodePort = []model.TLSPassthroughListener{
	{
		Name:     "ing-sslpassthru-ingress-dummy-namespace-sslpassthru.example.com",
		Sources:  sslPassthruSources,
		Port:     443,
		Hostname: "sslpassthru.example.com",
		Routes: []model.TLSPassthroughRoute{
			{
				Hostnames: []string{
					"sslpassthru.example.com",
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
		},
		Service: &model.Service{
			Type:             "NodePort",
			InsecureNodePort: uint32p(30000),
			SecureNodePort:   uint32p(30001),
		},
	},
}

// sslPassthruMultiplePaths tests when there are multiple paths, with one being '/'
var sslPassthruMultiplePaths = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/tls-passthrough": "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		Rules: []networkingv1.IngressRule{
			{
				Host: "sslpassthru.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path: "/prefix",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
								PathType: &exactPathType,
							},
							{
								Path: "/",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "dummy-backend",
										Port: networkingv1.ServiceBackendPort{
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

var sslPassthruMultiplePathsTLSListeners = []model.TLSPassthroughListener{
	{
		Name:     "ing-sslpassthru-ingress-dummy-namespace-sslpassthru.example.com",
		Sources:  sslPassthruSources,
		Port:     443,
		Hostname: "sslpassthru.example.com",
		Routes: []model.TLSPassthroughRoute{
			{
				Hostnames: []string{
					"sslpassthru.example.com",
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
		},
	},
}

// sslPassthruDefaultBackend tests when there's a default backend supplied
var sslPassthruDefaultBackend = networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "sslpassthru-ingress",
		Namespace: "dummy-namespace",
		Annotations: map[string]string{
			"ingress.cilium.io/tls-passthrough": "true",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: stringp("cilium"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend",
				Port: networkingv1.ServiceBackendPort{
					Number: 8080,
				},
			},
		},
		Rules: []networkingv1.IngressRule{},
	},
}

type passthruTestcase struct {
	ingress networkingv1.Ingress
	want    []model.TLSPassthroughListener
}

func TestIngressPassthrough(t *testing.T) {
	tests := map[string]passthruTestcase{
		"Cilium test ingress with SSL Passthrough": {
			ingress: sslPassthru,
			want:    sslPassthruTLSListeners,
		},
		"Cilium test ingress with SSL Passthrough, no host set": {
			ingress: sslPassthruNoHost,
			want:    emptyTLSListeners,
		},
		"Cilium test ingress with SSL Passthrough, host but no rule": {
			ingress: sslPassthruNoRule,
			want:    emptyTLSListeners,
		},
		"Cilium test ingress with SSL Passthrough, prefix path rule": {
			ingress: sslPassthruExtraPath,
			want:    emptyTLSListeners,
		},
		"Cilium test ingress with SSL Passthrough and default backend": {
			ingress: sslPassthruDefaultBackend,
			want:    emptyTLSListeners,
		},
		"Cilium test ingress with SSL Passthrough, multiple path rules, one valid": {
			ingress: sslPassthruMultiplePaths,
			want:    sslPassthruMultiplePathsTLSListeners,
		},
		"Cilium test ingress with SSL Passthrough, Nodeport Service annotations": {
			ingress: sslPassthruNodePort,
			want:    sslPassthruTLSListenersNodePort,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			listeners := IngressPassthrough(tc.ingress, 443)

			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}
