// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var basicHTTP = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway: gatewayv1beta1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: "gateway.networking.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "prod-web-gw",
					Port:     80,
					Protocol: "HTTP",
				},
			},
		},
	},
	HTTPRoutes: []gatewayv1beta1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-app-1",
				Namespace: "default",
			},
			Spec: gatewayv1beta1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
					ParentRefs: []gatewayv1beta1.ParentReference{
						{
							Name: "my-gateway",
						},
					},
				},
				Rules: []gatewayv1beta1.HTTPRouteRule{
					{
						Matches: []gatewayv1beta1.HTTPRouteMatch{
							{
								Path: &gatewayv1beta1.HTTPPathMatch{
									Type:  model.AddressOf[gatewayv1beta1.PathMatchType]("PathPrefix"),
									Value: model.AddressOf("/bar"),
								},
							},
						},
						BackendRefs: []gatewayv1beta1.HTTPBackendRef{
							{
								BackendRef: gatewayv1beta1.BackendRef{
									BackendObjectReference: gatewayv1beta1.BackendObjectReference{
										Name: "my-service",
										Port: model.AddressOf[gatewayv1beta1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
	},
	Services: []corev1.Service{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-service",
				Namespace: "default",
			},
		},
	},
}
var basicHTTPListeners = []model.HTTPListener{
	{
		Name: "prod-web-gw",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "my-gateway",
				Namespace: "default",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1beta1",
				Kind:      "Gateway",
			},
		},
		Address:  "",
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/bar",
				},
				Backends: []model.Backend{
					{
						Name:      "my-service",
						Namespace: "default",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var basicTLS = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway: gatewayv1beta1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: "gateway.networking.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "prod-web-gw",
					Port:     443,
					Protocol: "TLS",
				},
			},
		},
	},
	TLSRoutes: []gatewayv1alpha2.TLSRoute{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-app-1",
				Namespace: "default",
			},
			Spec: gatewayv1alpha2.TLSRouteSpec{
				CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
					ParentRefs: []gatewayv1beta1.ParentReference{
						{
							Name: "my-gateway",
						},
					},
				},
				Hostnames: []gatewayv1alpha2.Hostname{
					"example.com",
				},
				Rules: []gatewayv1alpha2.TLSRouteRule{
					{
						BackendRefs: []gatewayv1beta1.BackendRef{
							{
								BackendObjectReference: gatewayv1alpha2.BackendObjectReference{
									Name: "my-service",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](443),
								},
							},
						},
					},
				},
			},
		},
	},
	Services: []corev1.Service{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-service",
				Namespace: "default",
			},
		},
	},
}

var simpleSameNamespaceTLSListeners = []model.TLSListener{
	{
		Name: "https",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "gateway-tlsroute",
				Namespace: "gateway-conformance-infra",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1beta1",
				Kind:      "Gateway",
			},
		},
		Address:  "",
		Port:     443,
		Hostname: "*",
		Routes: []model.TLSRoute{
			{
				Hostnames: []string{
					"abc.example.com",
				},
				Backends: []model.Backend{
					{
						Name:      "tls-backend",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 443,
						},
					},
				},
			},
		},
	},
}

var basicTLSListeners = []model.TLSListener{
	{
		Name: "prod-web-gw",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "my-gateway",
				Namespace: "default",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1beta1",
				Kind:      "Gateway",
			},
		},
		Address:  "",
		Port:     443,
		Hostname: "*",
		Routes: []model.TLSRoute{
			{
				Hostnames: []string{
					"example.com",
				},
				Backends: []model.Backend{
					{
						Name:      "my-service",
						Namespace: "default",
						Port: &model.BackendPort{
							Port: 443,
						},
					},
				},
			},
		},
	},
}

var simpleSameNamespaceTLS = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceTLSGateway,
	TLSRoutes: []gatewayv1alpha2.TLSRoute{
		sameNamespaceTLSRoute,
	},
	Services: allServices,
}

var crossNamespaceHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      backendNamespaceGateway,
	HTTPRoutes: []gatewayv1beta1.HTTPRoute{
		crossNamespaceHTTPRoute,
	},
	Services: allServices,
}
var crossNamespaceHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "backend-namespaces",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Backends: []model.Backend{
					{
						Name:      "web-backend",
						Namespace: "gateway-conformance-web-backend",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var exactPathMatchingHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes: []gatewayv1beta1.HTTPRoute{
		exactPathMatchingHTTPRoute,
	},
	Services: allServices,
}
var exactPathMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/one"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/two"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var headerMatchingHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes: []gatewayv1beta1.HTTPRoute{
		headerMatchingHTTPRoute,
	},
	Services: allServices,
}
var headerMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "one"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "two"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "two"},
					},
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "orange"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Prefix: "", Exact: "blue", Regex: ""},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "blue"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "red"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "yellow"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra", Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var hostnameIntersectionHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      *hostnameIntersectionGateway,
	HTTPRoutes:   hostnameIntersectionHTTPRoutes,
	Services:     allServices,
}
var hostnameIntersectionHTTPListeners = []model.HTTPListener{
	{
		Name:     "listener-1",
		Sources:  []model.FullyQualifiedResource{{Name: "httproute-hostname-intersection", Namespace: "gateway-conformance-infra"}},
		Port:     80,
		Hostname: "very.specific.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"very.specific.com"},
				PathMatch: model.StringMatch{Prefix: "/s1"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				Hostnames: []string{"very.specific.com"},
				PathMatch: model.StringMatch{Prefix: "/s3"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-2",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-hostname-intersection",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*.wildcard.io",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"bar.wildcard.io", "foo.bar.wildcard.io", "foo.wildcard.io"},
				PathMatch: model.StringMatch{Prefix: "/s2"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-3",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-hostname-intersection",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*.anotherwildcard.io",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"*.anotherwildcard.io"},
				PathMatch: model.StringMatch{Prefix: "/s4"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var listenerHostnameMatchingHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      *listenerHostnameMatchingGateway,
	HTTPRoutes:   listenerHostnameMatchingHTTPRoutes,
	Services:     allServices,
}
var listenerHostnameMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "listener-1",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "bar.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"bar.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-2",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "foo.bar.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"foo.bar.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-3",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra"},
		},
		Port:     80,
		Hostname: "*.bar.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"*.bar.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-4",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*.foo.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"*.foo.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var matchingAcrossHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   matchingAcrossHTTPRoutes,
	Services:     allServices,
}
var matchingAcrossHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"example.com", "example.net"},
				PathMatch: model.StringMatch{Exact: "/"},
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "one"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				Hostnames:    []string{"example.com"},
				PathMatch:    model.StringMatch{Exact: "/v2"},
				HeadersMatch: []model.KeyValueMatch{{Key: "version", Match: model.StringMatch{Exact: "two"}}},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var matchingHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   matchingHTTPRoutes,
	Services:     allServices,
}
var matchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port: 80, Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/"},
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "one"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/v2"},
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "two"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var queryParamMatchingHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   queryParamMatchingHTTPRoutes,
	Services:     allServices,
}
var queryParamMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "animal",
						Match: model.StringMatch{Exact: "whale"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "animal",
						Match: model.StringMatch{Exact: "dolphin"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "animal",
						Match: model.StringMatch{Exact: "dolphin"},
					},
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "blue"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "ANIMAL",
						Match: model.StringMatch{Exact: "Whale"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var requestHeaderModifierHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   requestHeaderModifierHTTPRoutes,
	Services:     allServices,
}
var requestHeaderModifierHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port: 80, Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/set"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "set-overwrites-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/add"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "add-appends-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/remove"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToRemove: []string{"X-Header-Remove"},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/multiple"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
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
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set-1",
							Value: "header-set-1",
						},
						{
							Name:  "X-Header-Set-2",
							Value: "header-set-2",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove-1",
						"X-Header-Remove-2",
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/case-insensitivity"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "header-add",
						},
					},
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "header-set",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove",
					},
				},
			},
		},
	},
}

var simpleSameNamespaceHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   simpleSameNamespaceHTTPRoutes,
	Services:     allServices,
}

var simpleSameNamespaceHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var methodMatchingHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   methodMatchingHTTPRoutes,
	Services:     allServices,
}

var methodMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Method: model.AddressOf("POST"),
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				Method: model.AddressOf("GET"),
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var requestRedirectHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   requestRedirectHTTPRoutes,
	Services:     allServices,
}
var requestRedirectHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Prefix: "/hostname-redirect"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					Hostname: model.AddressOf("example.com"),
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/status-code-301"},
				Backends:  []model.Backend{},
				DirectResponse: &model.DirectResponse{
					StatusCode: 500,
				},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					StatusCode: model.AddressOf(301),
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/host-and-status"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					Hostname:   model.AddressOf("example.com"),
					StatusCode: model.AddressOf(301),
				},
			},
		},
	},
}

var responseHeaderModifierHTTPInput = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway:      sameNamespaceGateway,
	HTTPRoutes:   responseHeaderModifierHTTPRoutes,
	Services:     allServices,
}
var responseHeaderModifierHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port: 80, Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Prefix: "/set"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "set-overwrites-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/add"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "add-appends-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/remove"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToRemove: []string{"X-Header-Remove"},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/multiple"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
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
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set-1",
							Value: "header-set-1",
						},
						{
							Name:  "X-Header-Set-2",
							Value: "header-set-2",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove-1",
						"X-Header-Remove-2",
					},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/case-insensitivity"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
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
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "header-set",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove",
					},
				},
			},
		},
	},
}

func TestHTTPGatewayAPI(t *testing.T) {
	tests := map[string]struct {
		input Input
		want  []model.HTTPListener
	}{
		"basic http": {
			input: basicHTTP,
			want:  basicHTTPListeners,
		},
		"Conformance/HTTPRouteSimpleSameNamespace": {
			input: simpleSameNamespaceHTTPInput,
			want:  simpleSameNamespaceHTTPListeners,
		},
		"Conformance/HTTPRouteCrossNamespace": {
			input: crossNamespaceHTTPInput,
			want:  crossNamespaceHTTPListeners,
		},
		"Conformance/HTTPExactPathMatching": {
			input: exactPathMatchingHTTPInput,
			want:  exactPathMatchingHTTPListeners,
		},
		"Conformance/HTTPRouteHeaderMatching": {
			input: headerMatchingHTTPInput,
			want:  headerMatchingHTTPListeners,
		},
		"Conformance/HTTPRouteHostnameIntersection": {
			input: hostnameIntersectionHTTPInput,
			want:  hostnameIntersectionHTTPListeners,
		},
		"Conformance/HTTPRouteListenerHostnameMatching": {
			input: listenerHostnameMatchingHTTPInput,
			want:  listenerHostnameMatchingHTTPListeners,
		},
		"Conformance/HTTPRouteMatchingAcrossRoutes": {
			input: matchingAcrossHTTPInput,
			want:  matchingAcrossHTTPListeners,
		},
		"Conformance/HTTPRouteMatching": {
			input: matchingHTTPInput,
			want:  matchingHTTPListeners,
		},
		"Conformance/HTTPRouteMethodMatching": {
			input: methodMatchingHTTPInput,
			want:  methodMatchingHTTPListeners,
		},
		"Conformance/HTTPRouteQueryParamMatching": {
			input: queryParamMatchingHTTPInput,
			want:  queryParamMatchingHTTPListeners,
		},
		"Conformance/HTTPRouteRequestHeaderModifier": {
			input: requestHeaderModifierHTTPInput,
			want:  requestHeaderModifierHTTPListeners,
		},
		"Conformance/HTTPRouteRequestRedirect": {
			input: requestRedirectHTTPInput,
			want:  requestRedirectHTTPListeners,
		},
		"Conformance/HTTPRouteResponseHeaderModifier": {
			input: responseHeaderModifierHTTPInput,
			want:  responseHeaderModifierHTTPListeners,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			listeners, _ := GatewayAPI(tc.input)
			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}

func TestTLSGatewayAPI(t *testing.T) {
	tests := map[string]struct {
		input Input
		want  []model.TLSListener
	}{
		"basic http": {
			input: basicTLS,
			want:  basicTLSListeners,
		},
		"Conformance/TLSRouteSimpleSameNamespace": {
			input: simpleSameNamespaceTLS,
			want:  simpleSameNamespaceTLSListeners,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, listeners := GatewayAPI(tc.input)
			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}
