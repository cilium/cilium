// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testhelpers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var ControllerTestFixture = []client.Object{
	// Cilium Gateway Class
	&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},

	// Secret used in Gateway
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		StringData: map[string]string{
			"tls.crt": "cert",
			"tls.key": "key",
		},
		Type: corev1.SecretTypeTLS,
	},

	// Gateway with valid TLS secret
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Hostname: ptr.To[gatewayv1.Hostname]("example.com"),
					Port:     443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "tls-secret",
							},
						},
					},
				},
			},
		},
	},

	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway-2",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Hostname: ptr.To[gatewayv1.Hostname]("example2.com"),
					Port:     443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{},
					},
				},
			},
		},
	},

	// Gateway with no TLS listener
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-no-tls",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
				},
			},
		},
	},

	// Gateway for TLSRoute
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-tlsroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Protocol: gatewayv1.TLSProtocolType,
					Port:     443,
				},
			},
		},
	},

	// Gateway with allowed route in same namespace only
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-from-same-namespace",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSame),
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes from ALL namespace
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-from-all-namespaces",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromAll),
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes with selector
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-namespaces-selector",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"gateway": "allowed",
								},
							},
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes invalid namespace selector
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-invalid-namespaces-selector",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSelector),
						},
					},
				},
			},
		},
	},
}

var NamespaceFixtures = []client.Object{
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "another-namespace",
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-with-allowed-gateway-selector",
			Labels: map[string]string{
				"gateway": "allowed",
			},
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-with-disallowed-gateway-selector",
			Labels: map[string]string{
				"gateway": "disallowed",
			},
		},
	},
}
