// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ingress

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var exactPathType = slim_networkingv1.PathTypeExact

var baseIngress = &slim_networkingv1.Ingress{
	ObjectMeta: slim_metav1.ObjectMeta{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
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
				Hosts:      []string{"another-very-secure.server.com"},
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
							},
						},
					},
				},
			},
		},
	},
}

var verySecureTLS = &v1.Secret{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "tls-very-secure-server-com",
		Namespace: "dummy-namespace",
	},
	Data: map[string][]byte{
		"tls.key": []byte("very-secure-key"),
		"tls.crt": []byte("very-secure-cert"),
	},
}

var anotherVerySecureTLS = &v1.Secret{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "tls-another-very-secure-server-com",
		Namespace: "dummy-namespace",
	},
	Data: map[string][]byte{
		"tls.key": []byte("another-very-secure-key"),
		"tls.crt": []byte("another-very-secure-cert"),
	},
}
