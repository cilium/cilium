// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var httpRouteFixture = []client.Object{
	// GatewayClass
	&gatewayv1beta1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1beta1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},
	// Gateway for valid HTTPRoute
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "http",
					Port:     80,
					Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.cilium.io"),
				},
			},
		},
		Status: gatewayv1beta1.GatewayStatus{},
	},

	// Gateway in another namespace
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-gateway",
			Namespace: "another-namespace",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name: "http",
					Port: 80,
					AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
						Namespaces: &gatewayv1beta1.RouteNamespaces{
							From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
						},
					},
				},
			},
		},
		Status: gatewayv1beta1.GatewayStatus{},
	},

	// Service for valid HTTPRoute
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-backend",
			Namespace: "default",
		},
	},

	// Service in another namespace
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-backend",
			Namespace: "another-namespace",
		},
	},

	// Deleting HTTPRoute
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-http-route",
			Namespace:         "default",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{},
	},

	// Valid HTTPRoute
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-http-route",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "dummy-gateway",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "dummy-backend",
								},
							},
						},
					},
				},
			},
		},
	},

	// HTTPRoute with nonexistent backend
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route-with-nonexistent-backend",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "dummy-gateway",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "nonexistent-backend",
								},
							},
						},
					},
				},
			},
		},
	},

	// HTTPRoute with cross namespace backend
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route-with-cross-namespace-backend",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "dummy-gateway",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name:      "dummy-backend",
									Namespace: model.AddressOf[gatewayv1beta1.Namespace]("another-namespace"),
								},
							},
						},
					},
				},
			},
		},
	},

	// HTTPRoute with unsupported backend
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route-with-unsupported-backend",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "dummy-gateway",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name:  "unsupported-backend",
									Group: GroupPtr("unsupported-group"),
									Kind:  KindPtr("UnsupportedKind"),
								},
							},
						},
					},
				},
			},
		},
	},

	// HTTPRoute with non-existent gateway
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route-with-nonexistent-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "non-existent-gateway",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "dummy-backend",
								},
							},
						},
					},
				},
			},
		},
	},

	// HTTPRoute with valid but not allowed gateway
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route-with-not-allowed-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name:      "dummy-gateway",
						Namespace: model.AddressOf[gatewayv1beta1.Namespace]("another-namespace"),
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "dummy-backend",
								},
							},
						},
					},
				},
			},
		},
	},

	// HTTPRoute with non-matching hostname with gateway listener
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route-with-non-matching-hostname",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "dummy-gateway",
					},
				},
			},
			Hostnames: []gatewayv1beta1.Hostname{
				"non-matching-hostname",
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "dummy-backend",
								},
							},
						},
					},
				},
			},
		},
	},
}

func Test_httpRouteReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(httpRouteFixture...).Build()
	r := &httpRouteReconciler{Client: c}

	t.Run("no http route", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-existing-http-route",
				Namespace: "default",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("http route exists but being deleted", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "deleting-http-route",
				Namespace: "default",
			},
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
	})

	t.Run("valid http route", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "valid-http-route",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
	})

	t.Run("http route with nonexistent backend", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-nonexistent-backend",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)
		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, "BackendNotFound", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with nonexistent gateway", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-nonexistent-gateway",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "InvalidHTTPRoute", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
	})

	t.Run("http route with valid but not allowed gateway", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-not-allowed-gateway",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "NotAllowedByListeners", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "HTTPRoute is not allowed", route.Status.RouteStatus.Parents[0].Conditions[0].Message)
	})

	t.Run("http route with non-matching hostname", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-non-matching-hostname",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "NoMatchingListenerHostname", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "No matching listener hostname", route.Status.RouteStatus.Parents[0].Conditions[0].Message)
	})

	t.Run("http route with cross namespace backend", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-cross-namespace-backend",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)
		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "RefNotPermitted", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "Cross namespace references are not allowed", route.Status.RouteStatus.Parents[0].Conditions[0].Message)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with un-supported backend", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-unsupported-backend",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1beta1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)
		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "InvalidKind", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "Unsupported backend kind UnsupportedKind", route.Status.RouteStatus.Parents[0].Conditions[0].Message)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})
}
