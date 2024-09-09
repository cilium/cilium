// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Gateway API Mesh Conformance test resources
// https://github.com/kubernetes-sigs/gateway-api/tree/main/conformance/tests

// Base manifest
// https://github.com/kubernetes-sigs/gateway-api/blob/main/conformance/mesh/manifests.yaml

var (
	httpAppProtocol string = "http"
	grpcAppProtocol string = "grpc"
)

// echo-v1 Service

var gammaEchoV1Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "echo-v1",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:        "http",
				Port:        80,
				TargetPort:  intstr.FromInt(8080),
				AppProtocol: &httpAppProtocol,
			},
			{
				Name:        "http-alt",
				Port:        8080,
				AppProtocol: &httpAppProtocol,
			},
			{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromInt(8443),
			},
			{
				Name: "tcp",
				Port: 9090,
			},
			{
				Name:        "grpc",
				Port:        7070,
				AppProtocol: &grpcAppProtocol,
			},
		},
		Selector: map[string]string{
			"app":     "echo",
			"version": "v1",
		},
	},
}

// echo-v2 Service

var gammaEchoV2Service = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "echo-v2",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:        "http",
				Port:        80,
				TargetPort:  intstr.FromInt(8080),
				AppProtocol: &httpAppProtocol,
			},
			{
				Name:        "http-alt",
				Port:        8080,
				AppProtocol: &httpAppProtocol,
			},
			{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromInt(8443),
			},
			{
				Name: "tcp",
				Port: 9090,
			},
			{
				Name:        "grpc",
				Port:        7070,
				AppProtocol: &grpcAppProtocol,
			},
		},
		Selector: map[string]string{
			"app":     "echo",
			"version": "v2",
		},
	},
}

// echo Service

var gammaEchoService = corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "echo",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:        "http",
				Port:        80,
				TargetPort:  intstr.FromInt(8080),
				AppProtocol: &httpAppProtocol,
			},
			{
				Name:        "http-alt",
				Port:        8080,
				AppProtocol: &httpAppProtocol,
			},
			{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromInt(8443),
			},
			{
				Name: "tcp",
				Port: 9090,
			},
			{
				Name:        "grpc",
				Port:        7070,
				AppProtocol: &grpcAppProtocol,
			},
		},
		Selector: map[string]string{
			"app": "echo",
		},
	},
}

// mesh-split HTTPRoute
var meshSplitHTTPRoute = gatewayv1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mesh-split",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{
				{
					Name:  "echo",
					Group: GroupPtr(corev1.SchemeGroupVersion.Group),
					Kind:  KindPtr("Service"),
				},
			},
		},
		Rules: []gatewayv1.HTTPRouteRule{
			{
				Matches: []gatewayv1.HTTPRouteMatch{
					{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptr.To(gatewayv1.PathMatchExact),
							Value: ptr.To("/v1"),
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "echo-v1",
								Port: ptr.To[gatewayv1.PortNumber](80),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1.HTTPRouteMatch{
					{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptr.To(gatewayv1.PathMatchExact),
							Value: ptr.To("/v2"),
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "echo-v2",
								Port: ptr.To[gatewayv1.PortNumber](80),
							},
						},
					},
				},
			},
		},
	},
}

// mesh-ports HTTPRoute
var meshPortsHTTPRoute = gatewayv1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mesh-ports",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{
				{
					Name:  "echo-v1",
					Group: GroupPtr(corev1.SchemeGroupVersion.Group),
					Kind:  KindPtr("Service"),
					Port:  ptr.To[gatewayv1.PortNumber](80),
				},
			},
		},
		Rules: []gatewayv1.HTTPRouteRule{
			{
				Filters: []gatewayv1.HTTPRouteFilter{
					{
						Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier,
						ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
							Set: []gatewayv1.HTTPHeader{
								{
									Name:  gatewayv1.HTTPHeaderName("X-Header-Set"),
									Value: "v1",
								},
							},
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "echo-v1",
								Port: ptr.To[gatewayv1.PortNumber](80),
							},
						},
					},
				},
			},
		},
	},
}

// mesh-frontend HTTPRoute
var meshFrontendHTTPRoute = gatewayv1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mesh-split-v1",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{
				{
					Name:  "echo-v2",
					Group: GroupPtr(corev1.SchemeGroupVersion.Group),
					Kind:  KindPtr("Service"),
					Port:  ptr.To[gatewayv1.PortNumber](80),
				},
			},
		},
		Rules: []gatewayv1.HTTPRouteRule{
			{
				Filters: []gatewayv1.HTTPRouteFilter{
					{
						Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier,
						ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
							Set: []gatewayv1.HTTPHeader{
								{
									Name:  gatewayv1.HTTPHeaderName("X-Header-Set"),
									Value: "set",
								},
							},
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "echo-v2",
								Port: ptr.To[gatewayv1.PortNumber](80),
							},
						},
					},
				},
			},
		},
	},
}
