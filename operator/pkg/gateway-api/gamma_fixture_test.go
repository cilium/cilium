// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var serviceTypeMeta = metav1.TypeMeta{
	Kind:       "Service",
	APIVersion: "v1",
}

var meshConformanceBaseFixture = []client.Object{
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo-v1",
			Namespace: "gateway-conformance-mesh",
		},
		TypeMeta: serviceTypeMeta,
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app":     "echo",
				"version": "v1",
			},
			Ports: []corev1.ServicePort{
				{
					Name:        "http",
					Port:        80,
					AppProtocol: ptr.To[string]("http"),
					TargetPort:  intstr.FromInt(80),
				},
				{
					Name:        "http-alt",
					Port:        8080,
					AppProtocol: ptr.To[string]("http"),
					TargetPort:  intstr.FromInt(8080),
				},
				{
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromInt(443),
				},
				{
					Name: "tcp",
					Port: 9090,
				},
				{
					Name:        "grpc",
					Port:        7070,
					AppProtocol: ptr.To[string]("grpc"),
				},
			},
		},
	},
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo-v2",
			Namespace: "gateway-conformance-mesh",
		},
		TypeMeta: serviceTypeMeta,
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app":     "echo",
				"version": "v2",
			},
			Ports: []corev1.ServicePort{
				{
					Name:        "http",
					Port:        80,
					AppProtocol: ptr.To[string]("http"),
					TargetPort:  intstr.FromInt(80),
				},
				{
					Name:        "http-alt",
					Port:        8080,
					AppProtocol: ptr.To[string]("http"),
					TargetPort:  intstr.FromInt(8080),
				},
				{
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromInt(443),
				},
				{
					Name: "tcp",
					Port: 9090,
				},
				{
					Name:        "grpc",
					Port:        7070,
					AppProtocol: ptr.To[string]("grpc"),
				},
			},
		},
	},
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo",
			Namespace: "gateway-conformance-mesh",
		},
		TypeMeta: serviceTypeMeta,
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "echo",
			},
			Ports: []corev1.ServicePort{
				{
					Name:        "http",
					Port:        80,
					AppProtocol: ptr.To[string]("http"),
					TargetPort:  intstr.FromInt(80),
				},
				{
					Name:        "http-alt",
					Port:        8080,
					AppProtocol: ptr.To[string]("http"),
					TargetPort:  intstr.FromInt(8080),
				},
				{
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromInt(443),
				},
				{
					Name: "tcp",
					Port: 9090,
				},
				{
					Name:        "grpc",
					Port:        7070,
					AppProtocol: ptr.To[string]("grpc"),
				},
			},
		},
	},
	meshSplit,
}

var meshSplit = &gatewayv1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mesh-split",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{
				{
					Group: ptr.To[gatewayv1.Group](""),
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Name:  "echo",
				},
			},
		},
		Rules: []gatewayv1.HTTPRouteRule{
			{
				Matches: []gatewayv1.HTTPRouteMatch{
					{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptr.To[gatewayv1.PathMatchType](gatewayv1.PathMatchExact),
							Value: ptr.To[string]("/v1"),
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
							Type:  ptr.To[gatewayv1.PathMatchType](gatewayv1.PathMatchExact),
							Value: ptr.To[string]("/v2"),
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

func meshSplitWithParentRefs(parentRefs []gatewayv1.ParentReference) *gatewayv1.HTTPRoute {
	hr := meshSplit.DeepCopy()

	hr.Spec.ParentRefs = parentRefs

	return hr
}
