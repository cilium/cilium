// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/operator/pkg/model"
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
