// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	basedGatewayTestdataDir = "testdata/gateway"
)

func GroupPtr(name string) *gatewayv1.Group {
	group := gatewayv1.Group(name)
	return &group
}

func KindPtr(name string) *gatewayv1.Kind {
	kind := gatewayv1.Kind(name)
	return &kind
}

func TestHTTPGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic http":          {},
		"multiple parentRefs": {},
		"Conformance/HTTPRouteSimpleSameNamespace":               {},
		"Conformance/HTTPRouteCrossNamespace":                    {},
		"Conformance/HTTPExactPathMatching":                      {},
		"Conformance/HTTPRouteHeaderMatching":                    {},
		"Conformance/HTTPRouteHostnameIntersection":              {},
		"Conformance/HTTPRouteListenerHostnameMatching":          {},
		"Conformance/HTTPRouteMatchingAcrossRoutes":              {},
		"Conformance/HTTPRouteMatching":                          {},
		"Conformance/HTTPRouteMethodMatching":                    {},
		"Conformance/HTTPRouteQueryParamMatching":                {},
		"Conformance/HTTPRouteRequestHeaderModifier":             {},
		"Conformance/HTTPRouteBackendRefsRequestHeaderModifier":  {},
		"Conformance/HTTPRouteRequestRedirect":                   {},
		"Conformance/HTTPRouteResponseHeaderModifier":            {},
		"Conformance/HTTPRouteBackendRefsResponseHeaderModifier": {},
		"Conformance/HTTPRouteRewriteHost":                       {},
		"Conformance/HTTPRouteRewritePath":                       {},
		"Conformance/HTTPRouteRequestMirror":                     {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			input := readGatewayInput(t, name)
			listeners, _ := GatewayAPI(input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)

			assert.Equal(t, toYaml(t, expected), toYaml(t, listeners), "Listeners did not match")
		})
	}
}

func TestTLSGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic tls http": {},
		"Conformance/TLSRouteSimpleSameNamespace": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			input := readGatewayInput(t, name)
			_, listeners := GatewayAPI(input)

			expected := []model.TLSPassthroughListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)
			assert.Equal(t, toYaml(t, expected), toYaml(t, listeners), "Listeners did not match")
		})
	}
}

func TestGRPCGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic grpc": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			input := readGatewayInput(t, name)

			listeners, _ := GatewayAPI(input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)
			assert.Equal(t, toYaml(t, expected), toYaml(t, listeners), "Listeners did not match")
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

func TestHTTPRequestMirrorNilFilterDoesNotPanic(t *testing.T) {
	routes := extractRoutes(80, nil, gatewayv1.HTTPRoute{
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
	}, nil, nil, nil)

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].RequestMirrors)
}

func TestHTTPRequestMirrorSameNamespaceIsKept(t *testing.T) {
	routes := extractRoutes(80, nil, gatewayv1.HTTPRoute{
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
	}, nil, nil)

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "default", routes[0].RequestMirrors[0].Backend.Namespace)
}

func TestHTTPRequestMirrorCrossNamespaceWithoutReferenceGrantIsDropped(t *testing.T) {
	routes := extractRoutes(80, nil, gatewayv1.HTTPRoute{
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
	}, nil, nil)

	require.Len(t, routes, 1)
	assert.Len(t, routes[0].Backends, 1)
	assert.Nil(t, routes[0].RequestMirrors)
}

func TestHTTPRequestMirrorCrossNamespaceWithReferenceGrantIsKept(t *testing.T) {
	routes := extractRoutes(80, nil, gatewayv1.HTTPRoute{
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
	}, nil, []gatewayv1beta1.ReferenceGrant{
		testReferenceGrant("other-ns", "default", "HTTPRoute"),
	})

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "other-ns", routes[0].RequestMirrors[0].Backend.Namespace)
}

func TestGRPCRequestMirrorNilFilterDoesNotPanic(t *testing.T) {
	routes := testGRPCRoutes(gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName("listener"),
					},
				},
			},
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
	routes := testGRPCRoutes(gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "same-namespace-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName("listener"),
					},
				},
			},
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
	routes := testGRPCRoutes(gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-namespace-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName("listener"),
					},
				},
			},
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
	routes := testGRPCRoutes(gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-namespace-grpc-mirror",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName("listener"),
					},
				},
			},
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
	}, nil, []gatewayv1beta1.ReferenceGrant{
		testReferenceGrant("other-ns", "default", "GRPCRoute"),
	})

	require.Len(t, routes, 1)
	require.Len(t, routes[0].RequestMirrors, 1)
	assert.Equal(t, "mirror-backend", routes[0].RequestMirrors[0].Backend.Name)
	assert.Equal(t, "other-ns", routes[0].RequestMirrors[0].Backend.Namespace)
}

func testGRPCRoutes(route gatewayv1.GRPCRoute, services []corev1.Service, serviceImports []mcsapiv1alpha1.ServiceImport, grants []gatewayv1beta1.ReferenceGrant) []model.HTTPRoute {
	listener := gatewayv1beta1.Listener{
		Name:     gatewayv1beta1.SectionName("listener"),
		Protocol: gatewayv1beta1.ProtocolType(gatewayv1.HTTPProtocolType),
	}
	return toGRPCRoutes(listener, nil, []gatewayv1.GRPCRoute{route}, services, serviceImports, grants)
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

func testReferenceGrant(namespace, fromNamespace, kind string) gatewayv1beta1.ReferenceGrant {
	return gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.Group(gatewayv1.GroupName),
					Kind:      gatewayv1.Kind(kind),
					Namespace: gatewayv1.Namespace(fromNamespace),
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: gatewayv1.Group(""),
					Kind:  gatewayv1.Kind("Service"),
				},
			},
		},
	}
}

func readGatewayInput(t *testing.T, testName string) Input {
	input := Input{}

	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gatewayclass.yaml"), &input.GatewayClass)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gateway.yaml"), &input.Gateway)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-httproute.yaml"), &input.HTTPRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-tlsroute.yaml"), &input.TLSRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-grpcroute.yaml"), &input.GRPCRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-service.yaml"), &input.Services)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-serviceimport.yaml"), &input.ServiceImports)

	return input
}
