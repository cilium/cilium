// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	basedGatewayTestdataDir = "testdata/gateway"
)

func TestHTTPGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic http":                                              {},
		"basic http nodeport service":                             {},
		"basic http external traffic policy":                      {},
		"basic http load balancer":                                {},
		"multiple parentRefs":                                     {},
		"cert manager gateway":                                    {},
		"Conformance/HTTPRouteSimpleSameNamespace":                {},
		"Conformance/HTTPRouteCrossNamespace":                     {},
		"Conformance/HTTPExactPathMatching":                       {},
		"Conformance/HTTPRouteHeaderMatching":                     {},
		"Conformance/HTTPRouteHostnameIntersection":               {},
		"Conformance/HTTPRouteListenerHostnameMatching":           {},
		"Conformance/HTTPRouteMatchingAcrossRoutes":               {},
		"Conformance/HTTPRouteMatching":                           {},
		"Conformance/HTTPRouteMethodMatching":                     {},
		"Conformance/HTTPRouteQueryParamMatching":                 {},
		"Conformance/HTTPRouteRequestHeaderModifier":              {},
		"Conformance/HTTPRouteBackendRefsRequestHeaderModifier":   {},
		"Conformance/HTTPRouteRequestRedirect":                    {},
		"Conformance/HTTPRouteResponseHeaderModifier":             {},
		"Conformance/HTTPRouteBackendRefsResponseHeaderModifier":  {},
		"Conformance/HTTPRouteRewriteHost":                        {},
		"Conformance/HTTPRouteRewritePath":                        {},
		"Conformance/HTTPRouteRequestMirror":                      {},
		"Conformance/HTTPRouteBackendTLSPolicy":                   {},
		"Conformance/HTTPRouteBackendTLSPolicySystemCA":           {},
		"Conformance/HTTPRouteBackendTLSPolicyConflictResolution": {},
		"Conformance/HTTPRouteBackendTLSPolicyInvalidCA":          {},
		"http external auth grpc":                                 {},
		"http external auth http":                                 {},
		"http external auth http tls":                             {},
		"http external auth grpc tls":                             {},
		"http external auth shared and no auth":                   {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)
			m := GatewayAPI(logger, input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)

			assert.Equal(t, toYaml(t, expected), toYaml(t, m.HTTP), "Listeners did not match")
		})
	}
}

func TestHTTPGatewayAPIFiltersSelectorNamespacesPerListener(t *testing.T) {
	selector := gatewayv1.NamespacesFromSelector
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	m := GatewayAPI(logger, Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "selector-listener-conflict-gateway",
				Namespace: "gateway-system",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http-selected",
						Hostname: ptr.To[gatewayv1.Hostname]("selected.example.test"),
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From:     &selector,
								Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"expose": "true"}},
							},
						},
					},
					{
						Name:     "http-unselected",
						Hostname: ptr.To[gatewayv1.Hostname]("unselected.example.test"),
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &selector,
								Selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "expose", Operator: metav1.LabelSelectorOpDoesNotExist},
								}},
							},
						},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "selector-conflict-route",
					Namespace: "backend-a",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "selector-listener-conflict-gateway",
								Namespace: ptr.To[gatewayv1.Namespace]("gateway-system"),
							},
						},
					},
					Hostnames: []gatewayv1.Hostname{
						"selected.example.test",
						"unselected.example.test",
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "api",
											Port: ptr.To[gatewayv1.PortNumber](80),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Namespaces: []corev1.Namespace{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "backend-a",
					Labels: map[string]string{"expose": "true"},
				},
			},
		},
		Services: []corev1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "api",
					Namespace: "backend-a",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{Port: 80}},
				},
			},
		},
	})

	require.Len(t, m.HTTP, 2)
	require.Equal(t, "http-selected", m.HTTP[0].Name)
	require.Len(t, m.HTTP[0].Routes, 1)
	assert.Equal(t, []string{"selected.example.test"}, m.HTTP[0].Routes[0].Hostnames)

	require.Equal(t, "http-unselected", m.HTTP[1].Name)
	assert.Empty(t, m.HTTP[1].Routes)
}

func TestHTTPAndGRPCGatewayAPIFiltersRoutesByListenerAllowedNamespaces(t *testing.T) {
	sameNamespace := gatewayv1.NamespacesFromSame
	allNamespaces := gatewayv1.NamespacesFromAll
	redirectStatusCode := 301
	redirectScheme := "https"
	grpcService := "grpc.Service"
	grpcMethod := "Get"
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	m := GatewayAPI(logger, Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform",
				Namespace: "gateway-ns",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &sameNamespace,
							},
						},
					},
					{
						Name:     "https",
						Hostname: ptr.To[gatewayv1.Hostname]("*.example.test"),
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &allNamespaces,
							},
						},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "http-to-https-redirect",
					Namespace: "gateway-ns",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:        "platform",
								SectionName: ptr.To[gatewayv1.SectionName]("http"),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Matches: []gatewayv1.HTTPRouteMatch{
								{
									Path: &gatewayv1.HTTPPathMatch{
										Type:  ptr.To(gatewayv1.PathMatchPathPrefix),
										Value: ptr.To("/"),
									},
								},
							},
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestRedirect,
									RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
										Scheme:     &redirectScheme,
										StatusCode: &redirectStatusCode,
									},
								},
							},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podinfo",
					Namespace: "app-ns",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					Hostnames: []gatewayv1.Hostname{"podinfo.example.test"},
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "platform",
								Namespace: ptr.To[gatewayv1.Namespace]("gateway-ns"),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "podinfo",
											Port: ptr.To[gatewayv1.PortNumber](9898),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		GRPCRoutes: []gatewayv1.GRPCRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc",
					Namespace: "app-ns",
				},
				Spec: gatewayv1.GRPCRouteSpec{
					Hostnames: []gatewayv1.Hostname{"grpc.example.test"},
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "platform",
								Namespace: ptr.To[gatewayv1.Namespace]("gateway-ns"),
							},
						},
					},
					Rules: []gatewayv1.GRPCRouteRule{
						{
							Matches: []gatewayv1.GRPCRouteMatch{
								{
									Method: &gatewayv1.GRPCMethodMatch{
										Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
										Service: &grpcService,
										Method:  &grpcMethod,
									},
								},
							},
							BackendRefs: []gatewayv1.GRPCBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "podinfo",
											Port: ptr.To[gatewayv1.PortNumber](9898),
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
					Name:      "podinfo",
					Namespace: "app-ns",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Port: 9898,
						},
					},
				},
			},
		},
	})

	require.Len(t, m.HTTP, 2)
	require.Equal(t, "http", m.HTTP[0].Name)
	require.Len(t, m.HTTP[0].Routes, 1)
	assert.NotNil(t, m.HTTP[0].Routes[0].RequestRedirect)
	assert.Empty(t, m.HTTP[0].Routes[0].Backends)

	require.Equal(t, "https", m.HTTP[1].Name)
	require.Len(t, m.HTTP[1].Routes, 2)
	assert.Equal(t, []string{"podinfo.example.test"}, m.HTTP[1].Routes[0].Hostnames)
	require.Len(t, m.HTTP[1].Routes[0].Backends, 1)
	assert.Equal(t, "podinfo", m.HTTP[1].Routes[0].Backends[0].Name)
	assert.Equal(t, []string{"grpc.example.test"}, m.HTTP[1].Routes[1].Hostnames)
	assert.True(t, m.HTTP[1].Routes[1].IsGRPC)
	require.Len(t, m.HTTP[1].Routes[1].Backends, 1)
	assert.Equal(t, "podinfo", m.HTTP[1].Routes[1].Backends[0].Name)
}

func TestTLSGatewayAPIFiltersRoutesByListenerAllowedNamespaces(t *testing.T) {
	sameNamespace := gatewayv1.NamespacesFromSame
	allNamespaces := gatewayv1.NamespacesFromAll
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	m := GatewayAPI(logger, Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform",
				Namespace: "gateway-ns",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "tls-same",
						Hostname: ptr.To[gatewayv1.Hostname]("tls.example.test"),
						Port:     443,
						Protocol: gatewayv1.TLSProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &sameNamespace,
							},
						},
					},
					{
						Name:     "tls-all",
						Hostname: ptr.To[gatewayv1.Hostname]("tls.example.test"),
						Port:     8443,
						Protocol: gatewayv1.TLSProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &allNamespaces,
							},
						},
					},
				},
			},
		},
		TLSRoutes: []gatewayv1.TLSRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls",
					Namespace: "app-ns",
				},
				Spec: gatewayv1.TLSRouteSpec{
					Hostnames: []gatewayv1.Hostname{"tls.example.test"},
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "platform",
								Namespace: ptr.To[gatewayv1.Namespace]("gateway-ns"),
							},
						},
					},
					Rules: []gatewayv1.TLSRouteRule{
						{
							BackendRefs: []gatewayv1.BackendRef{
								{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "podinfo",
										Port: ptr.To[gatewayv1.PortNumber](9898),
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
					Name:      "podinfo",
					Namespace: "app-ns",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Port: 9898,
						},
					},
				},
			},
		},
	})

	require.Len(t, m.TLSPassthrough, 2)
	require.Equal(t, "tls-same", m.TLSPassthrough[0].Name)
	assert.Empty(t, m.TLSPassthrough[0].Routes)

	require.Equal(t, "tls-all", m.TLSPassthrough[1].Name)
	require.Len(t, m.TLSPassthrough[1].Routes, 1)
	assert.Equal(t, []string{"tls.example.test"}, m.TLSPassthrough[1].Routes[0].Hostnames)
	require.Len(t, m.TLSPassthrough[1].Routes[0].Backends, 1)
	assert.Equal(t, "podinfo", m.TLSPassthrough[1].Routes[0].Backends[0].Name)
}

func TestTLSGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic tls http": {},
		"Conformance/TLSRouteSimpleSameNamespace":  {},
		"Conformance/TLSRouteHostnameIntersection": {},
		"mixed protocol listeners TLSRoute":        {},
		"tls weighted backends":                    {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)
			m := GatewayAPI(logger, input)

			expected := []model.TLSPassthroughListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)
			assert.Equal(t, toYaml(t, expected), toYaml(t, m.TLSPassthrough), "Listeners did not match")
		})
	}
}

func TestGRPCGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic grpc": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)

			m := GatewayAPI(logger, input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)
			assert.Equal(t, toYaml(t, expected), toYaml(t, m.HTTP), "Listeners did not match")
		})
	}
}

func TestL4GatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic l4": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)
			m := GatewayAPI(logger, input)

			expected := []model.L4Listener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)

			assert.Equal(t, toYaml(t, expected), toYaml(t, m.L4), "Listeners did not match")
		})
	}
}

func TestL4GatewayAPIFiltersRoutesByListenerAllowedNamespaces(t *testing.T) {
	sameNamespace := gatewayv1.NamespacesFromSame
	allNamespaces := gatewayv1.NamespacesFromAll
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	m := GatewayAPI(logger, Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform",
				Namespace: "gateway-ns",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "tcp-same",
						Port:     9000,
						Protocol: gatewayv1.TCPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &sameNamespace,
							},
						},
					},
					{
						Name:     "tcp-all",
						Port:     9001,
						Protocol: gatewayv1.TCPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &allNamespaces,
							},
						},
					},
					{
						Name:     "udp-same",
						Port:     9002,
						Protocol: gatewayv1.UDPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &sameNamespace,
							},
						},
					},
					{
						Name:     "udp-all",
						Port:     9003,
						Protocol: gatewayv1.UDPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: &allNamespaces,
							},
						},
					},
				},
			},
		},
		TCPRoutes: []gatewayv1alpha2.TCPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tcp-same",
					Namespace: "app-ns",
				},
				Spec: gatewayv1alpha2.TCPRouteSpec{
					CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
						ParentRefs: []gatewayv1alpha2.ParentReference{
							{
								Name:        "platform",
								Namespace:   ptr.To[gatewayv1.Namespace]("gateway-ns"),
								SectionName: ptr.To[gatewayv1.SectionName]("tcp-same"),
							},
						},
					},
					Rules: []gatewayv1alpha2.TCPRouteRule{
						{
							BackendRefs: []gatewayv1alpha2.BackendRef{
								{
									BackendObjectReference: gatewayv1alpha2.BackendObjectReference{
										Name: "tcp-backend",
										Port: ptr.To[gatewayv1.PortNumber](9000),
									},
								},
							},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tcp-all",
					Namespace: "app-ns",
				},
				Spec: gatewayv1alpha2.TCPRouteSpec{
					CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
						ParentRefs: []gatewayv1alpha2.ParentReference{
							{
								Name:        "platform",
								Namespace:   ptr.To[gatewayv1.Namespace]("gateway-ns"),
								SectionName: ptr.To[gatewayv1.SectionName]("tcp-all"),
							},
						},
					},
					Rules: []gatewayv1alpha2.TCPRouteRule{
						{
							BackendRefs: []gatewayv1alpha2.BackendRef{
								{
									BackendObjectReference: gatewayv1alpha2.BackendObjectReference{
										Name: "tcp-backend",
										Port: ptr.To[gatewayv1.PortNumber](9000),
									},
								},
							},
						},
					},
				},
			},
		},
		UDPRoutes: []gatewayv1alpha2.UDPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "udp-same",
					Namespace: "app-ns",
				},
				Spec: gatewayv1alpha2.UDPRouteSpec{
					CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
						ParentRefs: []gatewayv1alpha2.ParentReference{
							{
								Name:        "platform",
								Namespace:   ptr.To[gatewayv1.Namespace]("gateway-ns"),
								SectionName: ptr.To[gatewayv1.SectionName]("udp-same"),
							},
						},
					},
					Rules: []gatewayv1alpha2.UDPRouteRule{
						{
							BackendRefs: []gatewayv1alpha2.BackendRef{
								{
									BackendObjectReference: gatewayv1alpha2.BackendObjectReference{
										Name: "udp-backend",
										Port: ptr.To[gatewayv1.PortNumber](9002),
									},
								},
							},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "udp-all",
					Namespace: "app-ns",
				},
				Spec: gatewayv1alpha2.UDPRouteSpec{
					CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
						ParentRefs: []gatewayv1alpha2.ParentReference{
							{
								Name:        "platform",
								Namespace:   ptr.To[gatewayv1.Namespace]("gateway-ns"),
								SectionName: ptr.To[gatewayv1.SectionName]("udp-all"),
							},
						},
					},
					Rules: []gatewayv1alpha2.UDPRouteRule{
						{
							BackendRefs: []gatewayv1alpha2.BackendRef{
								{
									BackendObjectReference: gatewayv1alpha2.BackendObjectReference{
										Name: "udp-backend",
										Port: ptr.To[gatewayv1.PortNumber](9002),
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
					Name:      "tcp-backend",
					Namespace: "app-ns",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{Port: 9000}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "udp-backend",
					Namespace: "app-ns",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{Port: 9002}},
				},
			},
		},
	})

	require.Len(t, m.L4, 4)
	require.Equal(t, "tcp-same", m.L4[0].Name)
	assert.Empty(t, m.L4[0].Routes)

	require.Equal(t, "tcp-all", m.L4[1].Name)
	require.Len(t, m.L4[1].Routes, 1)
	require.Len(t, m.L4[1].Routes[0].Backends, 1)
	assert.Equal(t, "tcp-backend", m.L4[1].Routes[0].Backends[0].Name)

	require.Equal(t, "udp-same", m.L4[2].Name)
	assert.Empty(t, m.L4[2].Routes)

	require.Equal(t, "udp-all", m.L4[3].Name)
	require.Len(t, m.L4[3].Routes, 1)
	require.Len(t, m.L4[3].Routes[0].Backends, 1)
	assert.Equal(t, "udp-backend", m.L4[3].Routes[0].Backends[0].Name)
}

func TestGPRCPathMatch(t *testing.T) {
	tests := map[string]struct {
		input gatewayv1.GRPCRouteMatch
		want  model.StringMatch
	}{
		"exact with service and method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
					Service: ptr.To("service"),
					Method:  ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Exact: "/service/method",
			},
		},
		"exact with only service specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
					Service: ptr.To("service"),
				},
			},
			want: model.StringMatch{
				Prefix: "/service/",
			},
		},
		"exact with only method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:   ptr.To(gatewayv1.GRPCMethodMatchExact),
					Method: ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Regex: "/.+/method",
			},
		},
		"regex with service and method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
					Service: ptr.To("service"),
					Method:  ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Regex: "/service/method",
			},
		},
		"regex with only service specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
					Service: ptr.To("service"),
				},
			},
			want: model.StringMatch{
				Regex: "/service/.+",
			},
		},
		"regex with only method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:   ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
					Method: ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Regex: "/.+/method",
			},
		},
		"regex with neither service nor method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type: ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
				},
			},
			want: model.StringMatch{
				Prefix: "/",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			match := toGRPCPathMatch(tc.input)
			assert.Equal(t, tc.want, match, "GPRC path match was not equal")
		})
	}
}

func TestHTTPRequestMirrorNilFilterDoesNotPanic(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	routes := extractRoutes(logger, 80, nil, gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-http-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestMirror,
						},
					},
				},
			},
		},
	}, nil, nil, nil, nil)

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].RequestMirrors)
}

func TestHTTPRequestMirrorSameNamespaceIsKept(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	routes := extractRoutes(logger, 80, nil, gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "same-namespace-http-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("mirror-backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}, []corev1.Service{
		testService("default", "backend", 8080),
		testService("default", "mirror-backend", 8080),
	}, nil, nil, nil)

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "default", routes[0].RequestMirrors[0].Backend.Namespace)
}

func TestHTTPRequestMirrorCrossNamespaceWithoutReferenceGrantIsDropped(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	routes := extractRoutes(logger, 80, nil, gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-namespace-http-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name:      gatewayv1.ObjectName("mirror-backend"),
									Namespace: ptr.To(gatewayv1.Namespace("other-ns")),
									Port:      ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}, []corev1.Service{
		testService("default", "backend", 8080),
		testService("other-ns", "mirror-backend", 8080),
	}, nil, nil, nil)

	require.Len(t, routes, 1)
	assert.Len(t, routes[0].Backends, 1)
	assert.Nil(t, routes[0].RequestMirrors)
}

func TestHTTPRequestMirrorCrossNamespaceWithReferenceGrantIsKept(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	routes := extractRoutes(logger, 80, nil, gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-namespace-http-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name:      gatewayv1.ObjectName("mirror-backend"),
									Namespace: ptr.To(gatewayv1.Namespace("other-ns")),
									Port:      ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}, []corev1.Service{
		testService("default", "backend", 8080),
		testService("other-ns", "mirror-backend", 8080),
	}, nil, []gatewayv1.ReferenceGrant{
		testReferenceGrant("other-ns", "default", "HTTPRoute"),
	}, nil)

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "other-ns", routes[0].RequestMirrors[0].Backend.Namespace)
}

func TestGRPCRequestMirrorNilFilterDoesNotPanic(t *testing.T) {
	routes := extractGRPCRoutes(nil, gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestMirror,
						},
					},
				},
			},
		},
	}, nil, nil, nil)

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].RequestMirrors)
}

func TestGRPCRequestMirrorSameNamespaceIsKept(t *testing.T) {
	routes := extractGRPCRoutes(nil, gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "same-namespace-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("mirror-backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}, []corev1.Service{
		testService("default", "backend", 8080),
		testService("default", "mirror-backend", 8080),
	}, nil, nil)

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "default", routes[0].RequestMirrors[0].Backend.Namespace)
}

func TestGRPCRequestMirrorCrossNamespaceWithoutReferenceGrantIsDropped(t *testing.T) {
	routes := extractGRPCRoutes(nil, gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-namespace-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name:      gatewayv1.ObjectName("mirror-backend"),
									Namespace: ptr.To(gatewayv1.Namespace("other-ns")),
									Port:      ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}, []corev1.Service{
		testService("default", "backend", 8080),
		testService("other-ns", "mirror-backend", 8080),
	}, nil, nil)

	require.Len(t, routes, 1)
	assert.Len(t, routes[0].Backends, 1)
	assert.Nil(t, routes[0].RequestMirrors)
}

func TestGRPCRequestMirrorCrossNamespaceWithReferenceGrantIsKept(t *testing.T) {
	routes := extractGRPCRoutes(nil, gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-namespace-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend"),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name:      gatewayv1.ObjectName("mirror-backend"),
									Namespace: ptr.To(gatewayv1.Namespace("other-ns")),
									Port:      ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}, []corev1.Service{
		testService("default", "backend", 8080),
		testService("other-ns", "mirror-backend", 8080),
	}, nil, []gatewayv1.ReferenceGrant{
		testReferenceGrant("other-ns", "default", "GRPCRoute"),
	})

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "other-ns", routes[0].RequestMirrors[0].Backend.Namespace)
}

func TestGatewayAPI_GatewayClassConfig(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	t.Run("returns nil telemetry when GatewayClassConfig telemetry is nil", func(t *testing.T) {
		m := GatewayAPI(logger, Input{
			GatewayClassConfig: &v2alpha1.CiliumGatewayClassConfig{},
		})

		assert.Nil(t, m.Telemetry)
	})
	t.Run("returns model with telemetry when GatewayClassConfig has access log config", func(t *testing.T) {
		m := GatewayAPI(logger, Input{
			Gateway: gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cilium",
				},
			},
			GatewayClassConfig: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					Telemetry: &v2alpha1.Telemetry{
						AccessLogs: []v2alpha1.AccessLogs{
							{
								Format: v2alpha1.AccessLogsFormatText,
								Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
							},
						},
					},
				},
			},
		})

		assert.Equal(t, &model.Telemetry{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "cilium",
			},
			AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
				model.AccessLogsTargetHTTP: {
					{
						Format: model.AccessLogsFormatText,
						Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
					},
				},
			},
		}, m.Telemetry)
	})
}

func TestGatewayAPI_GatewayClassConfigTelemetry(t *testing.T) {
	nn := types.NamespacedName{
		Namespace: "default",
		Name:      "cilium",
	}
	tests := []struct {
		name string
		cfg  *v2alpha1.Telemetry
		want *model.Telemetry
	}{
		{
			name: "telemetry config without access logs",
			cfg:  &v2alpha1.Telemetry{},
			want: &model.Telemetry{
				NamespacedName: nn,
			},
		},
		{
			name: "text access logs",
			cfg: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{
					{
						Format: v2alpha1.AccessLogsFormatText,
						Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
					},
				},
			},
			want: &model.Telemetry{
				NamespacedName: nn,
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {
						{
							Format: model.AccessLogsFormatText,
							Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						},
					},
				},
			},
		},
		{
			name: "json access logs",
			cfg: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{
					{
						Format: v2alpha1.AccessLogsFormatJSON,
						JSON: map[string]string{
							"method": "%REQ(:METHOD)%",
						},
					},
				},
			},
			want: &model.Telemetry{
				NamespacedName: nn,
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {
						{
							Format: model.AccessLogsFormatJSON,
							JSON: map[string]string{
								"method": "%REQ(:METHOD)%",
							},
						},
					},
				},
			},
		},
		{
			name: "text access logs with tcp target",
			cfg: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{
					{
						Format: v2alpha1.AccessLogsFormatText,
						Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						Targets: []v2alpha1.AccessLogsTarget{
							v2alpha1.AccessLogsTargetTCP,
						},
					},
				},
			},
			want: &model.Telemetry{
				NamespacedName: nn,
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetTCP: {
						{
							Format: model.AccessLogsFormatText,
							Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						},
					},
				},
			},
		},
		{
			name: "target-specific access logs",
			cfg: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{
					{
						Format: v2alpha1.AccessLogsFormatText,
						Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						Targets: []v2alpha1.AccessLogsTarget{
							v2alpha1.AccessLogsTargetHTTP,
						},
					},
					{
						Format: v2alpha1.AccessLogsFormatJSON,
						JSON: map[string]string{
							"response_code": "%RESPONSE_CODE%",
						},
						Targets: []v2alpha1.AccessLogsTarget{
							v2alpha1.AccessLogsTargetTCP,
						},
					},
				},
			},
			want: &model.Telemetry{
				NamespacedName: nn,
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {
						{
							Format: model.AccessLogsFormatText,
							Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						},
					},
					model.AccessLogsTargetTCP: {
						{
							Format: model.AccessLogsFormatJSON,
							JSON: map[string]string{
								"response_code": "%RESPONSE_CODE%",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toTelemetryConfig(nn, tt.cfg))
		})
	}
}

func testService(namespace, name string, port int32) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port: port,
				},
			},
		},
	}
}

func testReferenceGrant(namespace, fromNamespace, kind string) gatewayv1.ReferenceGrant {
	return gatewayv1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.Group(gatewayv1.GroupName),
					Kind:      gatewayv1.Kind(kind),
					Namespace: gatewayv1.Namespace(fromNamespace),
				},
			},
			To: []gatewayv1.ReferenceGrantTo{
				{
					Group: gatewayv1.Group(""),
					Kind:  gatewayv1.Kind("Service"),
				},
			},
		},
	}
}

func readGatewayInput(t *testing.T, testName string) Input {
	t.Helper()
	input := Input{}

	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gatewayclass.yaml"), &input.GatewayClass)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gatewayclassconfig.yaml"), &input.GatewayClassConfig)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gateway.yaml"), &input.Gateway)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-httproute.yaml"), &input.HTTPRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-tlsroute.yaml"), &input.TLSRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-grpcroute.yaml"), &input.GRPCRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-namespace.yaml"), &input.Namespaces)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-tcproute.yaml"), &input.TCPRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-udproute.yaml"), &input.UDPRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-service.yaml"), &input.Services)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-serviceimport.yaml"), &input.ServiceImports)

	btlspMapFixture := &BackendTLSPolicyMapFixture{}
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-backendtlspolicy.yaml"), btlspMapFixture)
	btlspMap, err := btlspMapFixture.ToBackendTLSPolicyMap()
	if err != nil {
		t.Fatal("Failed reading a BackendTLSPolicy fixture", err)
	}
	input.BackendTLSPolicyMap = btlspMap

	return input
}
