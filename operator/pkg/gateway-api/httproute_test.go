// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"
)

// We test this here and not in httproute_reconcile_test.go because calling
// Reconcile() directly won't invoke the hasMatchingGatewayParent() predicate.
func Test_httpRouteReconciler_hasMatchingGatewayParent(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name     string
		objects  []client.Object
		route    *gatewayv1.HTTPRoute
		expected bool
	}{
		{
			name: "matching gateway parent",
			objects: []client.Object{
				&gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "cilium",
					},
				},
				&gatewayv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
					},
					Spec: gatewayv1.GatewayClassSpec{
						ControllerName: "io.cilium/gateway-controller",
					},
				},
			},
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name: "my-gateway",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "no matching gateway parent - different controller",
			objects: []client.Object{
				&gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "other",
					},
				},
				&gatewayv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "other",
					},
					Spec: gatewayv1.GatewayClassSpec{
						ControllerName: "other.io/gateway-controller",
					},
				},
			},
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name: "my-gateway",
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name:    "no gateway parent",
			objects: []client.Object{},
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{},
					},
				},
			},
			expected: false,
		},
		{
			name: "cross namespace gateway parent",
			objects: []client.Object{
				&gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-gateway",
						Namespace: "other",
					},
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "cilium",
					},
				},
				&gatewayv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
					},
					Spec: gatewayv1.GatewayClassSpec{
						ControllerName: "io.cilium/gateway-controller",
					},
				},
			},
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "my-gateway",
								Namespace: ptr.To[gatewayv1.Namespace]("other"),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "non-gateway parent ref",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-service",
						Namespace: "default",
					},
				},
			},
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:  "my-service",
								Group: ptr.To[gatewayv1.Group](""),
								Kind:  ptr.To[gatewayv1.Kind]("Service"),
							},
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with test objects
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := &httpRouteReconciler{
				Client: c,
				logger: hivetest.Logger(t),
			}

			result := r.hasMatchingGatewayParent()(tt.route)
			require.Equal(t, tt.expected, result)
		})
	}
}
