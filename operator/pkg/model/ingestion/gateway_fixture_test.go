// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

// Gateway API Conformance test resources
// https://github.com/kubernetes-sigs/gateway-api/tree/main/conformance/tests

// Base manifest
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/base/manifests.yaml
var sameNamespaceGateway = gatewayv1beta1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "same-namespace",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1beta1.Listener{
			{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1beta1.HTTPProtocolType,
				TLS:      nil,
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
		},
	},
}

// Base manifest
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.6.1/conformance/base/tls-route-simple-same-namespace.yaml
var sameNamespaceTLSGateway = gatewayv1beta1.Gateway{
	TypeMeta: metav1.TypeMeta{
		Kind:       "Gateway",
		APIVersion: "gateway.networking.k8s.io/v1beta1",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name:      "gateway-tlsroute",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1beta1.Listener{
			{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1beta1.TLSProtocolType,
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
				TLS: &gatewayv1beta1.GatewayTLSConfig{
					Mode: model.AddressOf(gatewayv1beta1.TLSModePassthrough),
				},
			},
		},
	},
}

// Base manifest
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.6.1/conformance/base/tls-route-simple-same-namespace.yaml
var sameNamespaceTLSRoute = gatewayv1alpha2.TLSRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "gateway-conformance-infra-test",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1alpha2.TLSRouteSpec{
		CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
			ParentRefs: []gatewayv1beta1.ParentReference{
				{
					Name:      "gateway-tlsroute",
					Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
				},
			},
		},
		Hostnames: []gatewayv1beta1.Hostname{
			"abc.example.com",
		},
		Rules: []gatewayv1alpha2.TLSRouteRule{
			{
				BackendRefs: []gatewayv1alpha2.BackendRef{
					{
						BackendObjectReference: gatewayv1beta1.BackendObjectReference{
							Name: "tls-backend",
							Port: model.AddressOf[gatewayv1beta1.PortNumber](443),
						},
					},
				},
			},
		},
	},
}

//var allNamespacesGateway = gatewayv1beta1.Gateway{
//	ObjectMeta: metav1.ObjectMeta{
//		Name:      "all-namespaces",
//		Namespace: "gateway-conformance-infra",
//	},
//	Spec: gatewayv1beta1.GatewaySpec{
//		GatewayClassName: "cilium",
//		Listeners: []gatewayv1beta1.Listener{
//			{
//				Name:     "http",
//				Port:     80,
//				Protocol: gatewayv1beta1.HTTPProtocolType,
//				TLS:      nil,
//				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
//					Namespaces: &gatewayv1beta1.RouteNamespaces{
//						From: model.AddressOf(gatewayv1beta1.NamespacesFromAll),
//					},
//				},
//			},
//		},
//	},
//}

var backendNamespaceGateway = gatewayv1beta1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "backend-namespaces",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1beta1.Listener{
			{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1beta1.HTTPProtocolType,
				TLS:      nil,
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"gateway-conformance": "backend",
							},
						},
					},
				},
			},
		},
	},
}

var allServices = []corev1.Service{
	infraBackEndV1Service,
	infraBackEndV2Service,
	infraBackEndV3Service,
	appBackEndV1Service,
	appBackEndV2Service,
	webBackendService,
	tlsBackendService,
}

var infraBackEndV1Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "infra-backend-v1",
		Namespace: "gateway-conformance-infra",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       8080,
				TargetPort: intstr.FromInt(3000),
			},
		},
		Selector: map[string]string{
			"app": "infra-backend-v1",
		},
	},
}
var infraBackEndV2Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "infra-backend-v2",
		Namespace: "gateway-conformance-infra",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       8080,
				TargetPort: intstr.FromInt(3000),
			},
		},
		Selector: map[string]string{
			"app": "infra-backend-v2",
		},
	},
}
var infraBackEndV3Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "infra-backend-v3",
		Namespace: "gateway-conformance-infra",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       8080,
				TargetPort: intstr.FromInt(3000),
			},
		},
		Selector: map[string]string{
			"app": "infra-backend-v3",
		},
	},
}
var appBackEndV1Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "app-backend-v1",
		Namespace: "gateway-conformance-app-backend",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       8080,
				TargetPort: intstr.FromInt(3000),
			},
		},
		Selector: map[string]string{
			"app": "app-backend-v1",
		},
	},
}
var appBackEndV2Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "app-backend-v2",
		Namespace: "gateway-conformance-app-backend",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       8080,
				TargetPort: intstr.FromInt(3000),
			},
		},
		Selector: map[string]string{
			"app": "app-backend-v2",
		},
	},
}
var webBackendService = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "web-backend",
		Namespace: "gateway-conformance-web-backend",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       8080,
				TargetPort: intstr.FromInt(3000),
			},
		},
		Selector: map[string]string{
			"app": "web-backend",
		},
	},
}

var tlsBackendService = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "tls-backend",
		Namespace: "gateway-conformance-infra",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "tcp",
				Port:       443,
				TargetPort: intstr.FromInt(8443),
			},
		},
		Selector: map[string]string{
			"app": "tls-backend",
		},
	},
}

// HTTPRoute cross namespace
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-cross-namespace.yaml
var crossNamespaceHTTPRoute = gatewayv1beta1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cross-namespace",
		Namespace: "gateway-conformance-web-backend",
	},
	Spec: gatewayv1beta1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
			ParentRefs: []gatewayv1beta1.ParentReference{
				{
					Name:      "backend-namespaces",
					Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
				},
			},
		},
		Rules: []gatewayv1beta1.HTTPRouteRule{
			{
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "web-backend",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute exact matching
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-exact-path-matching.yaml
var exactPathMatchingHTTPRoute = gatewayv1beta1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "exact-matching",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
			ParentRefs: []gatewayv1beta1.ParentReference{
				{
					Name: "same-namespace",
				},
			},
		},
		Rules: []gatewayv1beta1.HTTPRouteRule{
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Path: &gatewayv1beta1.HTTPPathMatch{
							Type:  model.AddressOf(gatewayv1beta1.PathMatchExact),
							Value: model.AddressOf("/one"),
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v1",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Path: &gatewayv1beta1.HTTPPathMatch{
							Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
							Value: model.AddressOf("/two"),
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v2",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
		},
	},
}

// HTTRRoute header matching
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-header-matching.yaml
var headerMatchingHTTPRoute = gatewayv1beta1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "header-matching",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
			ParentRefs: []gatewayv1beta1.ParentReference{
				{
					Name: "same-namespace",
				},
			},
		},
		Rules: []gatewayv1beta1.HTTPRouteRule{
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "version",
								Value: "one",
							},
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v1",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "version",
								Value: "two",
							},
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v2",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "version",
								Value: "two",
							},
							{
								Name:  "color",
								Value: "orange",
							},
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v1",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "color",
								Value: "blue",
							},
						},
					},
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "color",
								Value: "blue",
							},
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v1",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1beta1.HTTPRouteMatch{
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "color",
								Value: "red",
							},
						},
					},
					{
						Headers: []gatewayv1beta1.HTTPHeaderMatch{
							{
								Name:  "color",
								Value: "yellow",
							},
						},
					},
				},
				BackendRefs: []gatewayv1beta1.HTTPBackendRef{
					{
						BackendRef: gatewayv1beta1.BackendRef{
							BackendObjectReference: gatewayv1beta1.BackendObjectReference{
								Name: "infra-backend-v2",
								Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute hostname intersection
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-hostname-intersection.yaml
var hostnameIntersectionGateway = &gatewayv1beta1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "httproute-hostname-intersection",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1beta1.Listener{
			{
				Name:     "listener-1",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("very.specific.com"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
			{
				Name:     "listener-2",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.wildcard.io"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
			{
				Name:     "listener-3",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.anotherwildcard.io"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
		},
	},
}
var hostnameIntersectionHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "specific-host-matches-listener-specific-host",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:      "httproute-hostname-intersection",
						Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"non.matching.com",
				"*.nonmatchingwildcard.io", // matches listener-1's specific host
				"very.specific.com",        // # matches listener-1's specific host
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/s1"),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "specific-host-matches-listener-wildcard-host",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:      "httproute-hostname-intersection",
						Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"non.matching.com",
				"wildcard.io",
				"foo.wildcard.io",     // matches listener-2's wildcard host
				"bar.wildcard.io",     // matches listener-2's wildcard host
				"foo.bar.wildcard.io", //matches listener-2's wildcard host
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/s2"),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wildcard-host-matches-listener-specific-host",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:      "httproute-hostname-intersection",
						Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"non.matching.com",
				"*.specific.com", // matches listener-1's wildcard host
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/s3"),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v3",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wildcard-host-matches-listener-wildcard-host",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:      "httproute-hostname-intersection",
						Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"*.anotherwildcard.io", // matches listener-3's wildcard host
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/s4"),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-intersecting-hosts",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:      "httproute-hostname-intersection",
						Namespace: model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"specific.but.wrong.com",
				"wildcard.io",
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/s5"),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute listener hostname matching
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-listener-hostname-matching.yaml
var listenerHostnameMatchingGateway = &gatewayv1beta1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "httproute-listener-hostname-matching",
		Namespace: "gateway-conformance-infra",
	},
	Spec: gatewayv1beta1.GatewaySpec{
		GatewayClassName: "cilium",
		Listeners: []gatewayv1beta1.Listener{
			{
				Name:     "listener-1",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("bar.com"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
			{
				Name:     "listener-2",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("foo.bar.com"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
			{
				Name:     "listener-3",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.bar.com"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
			{
				Name:     "listener-4",
				Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.foo.com"),
				Port:     80,
				Protocol: "HTTP",
				AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
					Namespaces: &gatewayv1beta1.RouteNamespaces{
						From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
					},
				},
			},
		},
	},
}
var listenerHostnameMatchingHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-v1",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:        "httproute-listener-hostname-matching",
						Namespace:   model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
						SectionName: model.AddressOf[gatewayv1beta1.SectionName]("listener-1"),
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-v2",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:        "httproute-listener-hostname-matching",
						Namespace:   model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
						SectionName: model.AddressOf[gatewayv1beta1.SectionName]("listener-2"),
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-v3",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:        "httproute-listener-hostname-matching",
						Namespace:   model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
						SectionName: model.AddressOf[gatewayv1beta1.SectionName]("listener-3"),
					},
					{
						Name:        "httproute-listener-hostname-matching",
						Namespace:   model.AddressOf[gatewayv1beta1.Namespace]("gateway-conformance-infra"),
						SectionName: model.AddressOf[gatewayv1beta1.SectionName]("listener-4"),
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v3",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute matching across routes
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-matching-across-routes.yaml
var matchingAcrossHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "matching-part1",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"example.com",
				"example.net",
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/"),
							},
							Headers: []gatewayv1beta1.HTTPHeaderMatch{
								{
									Name:  "version",
									Value: "one",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "matching-part2",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"example.com",
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/v2"),
							},
							Headers: []gatewayv1beta1.HTTPHeaderMatch{
								{
									Name:  "version",
									Value: "two",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute matching
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-matching.yaml
var matchingHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "matching",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/"),
							},
							Headers: []gatewayv1beta1.HTTPHeaderMatch{
								{
									Name:  "version",
									Value: "one",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/v2"),
							},
							Headers: []gatewayv1beta1.HTTPHeaderMatch{
								{
									Name:  "version",
									Value: "two",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute query param matching
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-query-param-matching.yaml
var queryParamMatchingHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "query-param-matching",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							QueryParams: []gatewayv1beta1.HTTPQueryParamMatch{
								{
									Name:  "animal",
									Value: "whale",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							QueryParams: []gatewayv1beta1.HTTPQueryParamMatch{
								{
									Name:  "animal",
									Value: "dolphin",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							QueryParams: []gatewayv1beta1.HTTPQueryParamMatch{
								{
									Name:  "animal",
									Value: "dolphin",
								},
								{
									Name:  "color",
									Value: "blue",
								},
							},
						},
						{
							QueryParams: []gatewayv1beta1.HTTPQueryParamMatch{
								{
									Name:  "ANIMAL",
									Value: "Whale",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v3",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute request header modifier
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-request-header-modifier.yaml
var requestHeaderModifierHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "request-header-modifier",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/set"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "RequestHeaderModifier",
							RequestHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Set: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Set",
										Value: "set-overwrites-values",
									},
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/add"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "RequestHeaderModifier",
							RequestHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Add: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Add",
										Value: "add-appends-values",
									},
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/remove"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "RequestHeaderModifier",
							RequestHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Remove: []string{
									"X-Header-Remove",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/multiple"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "RequestHeaderModifier",
							RequestHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Set: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Set-1",
										Value: "header-set-1",
									},
									{
										Name:  "X-Header-Set-2",
										Value: "header-set-2",
									},
								},
								Add: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Add-1",
										Value: "header-add-1",
									},
									{
										Name:  "X-Header-Add-2",
										Value: "header-add-2",
									},
									{
										Name:  "X-Header-Add-3",
										Value: "header-add-3",
									},
								},
								Remove: []string{
									"X-Header-Remove-1",
									"X-Header-Remove-2",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchExact),
								Value: model.AddressOf("/case-insensitivity"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "RequestHeaderModifier",
							RequestHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Set: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Set",
										Value: "header-set",
									},
								},
								Add: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Add",
										Value: "header-add",
									},
								},
								Remove: []string{
									"X-Header-Remove",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute simple same namespace
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/tests/httproute-simple-same-namespace.yaml
var simpleSameNamespaceHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-conformance-infra-test",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute method matching
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.6.0/conformance/tests/httproute-method-matching.yaml
var methodMatchingHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "method-matching",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Method: model.AddressOf[gatewayv1beta1.HTTPMethod]("POST"),
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Method: model.AddressOf[gatewayv1beta1.HTTPMethod]("GET"),
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v2",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute request redirect
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.6.0/conformance/tests/httproute-request-redirect.yaml
var requestRedirectHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "request-redirect",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/hostname-redirect"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: gatewayv1beta1.HTTPRouteFilterRequestRedirect,
							RequestRedirect: &gatewayv1beta1.HTTPRequestRedirectFilter{
								Hostname: model.AddressOf[gatewayv1beta1.PreciseHostname]("example.com"),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/status-code-301"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: gatewayv1beta1.HTTPRouteFilterRequestRedirect,
							RequestRedirect: &gatewayv1beta1.HTTPRequestRedirectFilter{
								StatusCode: model.AddressOf(301),
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/host-and-status"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: gatewayv1beta1.HTTPRouteFilterRequestRedirect,
							RequestRedirect: &gatewayv1beta1.HTTPRequestRedirectFilter{
								Hostname:   model.AddressOf[gatewayv1beta1.PreciseHostname]("example.com"),
								StatusCode: model.AddressOf(301),
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}

// HTTPRoute response header modifier
// https://github.com/kubernetes-sigs/gateway-api/blob/v0.6.0/conformance/tests/httproute-response-header-modifier.yaml
var responseHeaderModifierHTTPRoutes = []gatewayv1beta1.HTTPRoute{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "response-header-modifier",
			Namespace: "gateway-conformance-infra",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "same-namespace",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/set"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "ResponseHeaderModifier",
							ResponseHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Set: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Set",
										Value: "set-overwrites-values",
									},
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/add"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "ResponseHeaderModifier",
							ResponseHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Add: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Add",
										Value: "add-appends-values",
									},
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/remove"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "ResponseHeaderModifier",
							ResponseHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Remove: []string{
									"X-Header-Remove",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/multiple"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "ResponseHeaderModifier",
							ResponseHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Set: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Set-1",
										Value: "header-set-1",
									},
									{
										Name:  "X-Header-Set-2",
										Value: "header-set-2",
									},
								},
								Add: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Add-1",
										Value: "header-add-1",
									},
									{
										Name:  "X-Header-Add-2",
										Value: "header-add-2",
									},
									{
										Name:  "X-Header-Add-3",
										Value: "header-add-3",
									},
								},
								Remove: []string{
									"X-Header-Remove-1",
									"X-Header-Remove-2",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
				{
					Matches: []gatewayv1beta1.HTTPRouteMatch{
						{
							Path: &gatewayv1beta1.HTTPPathMatch{
								Type:  model.AddressOf[gatewayv1beta1.PathMatchType](gatewayv1beta1.PathMatchPathPrefix),
								Value: model.AddressOf("/case-insensitivity"),
							},
						},
					},
					Filters: []gatewayv1beta1.HTTPRouteFilter{
						{
							Type: "ResponseHeaderModifier",
							ResponseHeaderModifier: &gatewayv1beta1.HTTPHeaderFilter{
								Set: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Set",
										Value: "header-set",
									},
								},
								Add: []gatewayv1beta1.HTTPHeader{
									{
										Name:  "X-Header-Add",
										Value: "header-add",
									},
									{
										Name:  "x-lowercase-add",
										Value: "lowercase-add",
									},
									{
										Name:  "x-Mixedcase-ADD-1",
										Value: "mixedcase-add-1",
									},
									{
										Name:  "X-mixeDcase-add-2",
										Value: "mixedcase-add-2",
									},
									{
										Name:  "X-UPPERCASE-ADD",
										Value: "uppercase-add",
									},
								},
								Remove: []string{
									"X-Header-Remove",
								},
							},
						},
					},
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "infra-backend-v1",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	},
}
