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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var (
	httpRFFinalizer = "batch.gateway.io/finalizer"

	httpRouteFixture = []client.Object{
		// GatewayClass
		&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cilium",
			},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "io.cilium/gateway-controller",
			},
		},

		// Gateway for valid HTTPRoute
		&gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Hostname: model.AddressOf[gatewayv1.Hostname]("*.cilium.io"),
					},
				},
			},
			Status: gatewayv1.GatewayStatus{},
		},

		// Gateway in another namespace
		&gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-gateway",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{
					{
						Name: "http",
						Port: 80,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: model.AddressOf(gatewayv1.NamespacesFromSame),
							},
						},
					},
				},
			},
			Status: gatewayv1.GatewayStatus{},
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

		// Service for reference grant in another namespace
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend-grant",
				Namespace: "another-namespace",
			},
		},

		// Deleting HTTPRoute
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "deleting-http-route",
				Namespace:         "default",
				Finalizers:        []string{httpRFFinalizer},
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
			},
			Spec: gatewayv1.HTTPRouteSpec{},
		},

		// Valid HTTPRoute
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-http-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: model.AddressOf[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with nonexistent backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-backend",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "nonexistent-backend",
										Port: model.AddressOf[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with cross namespace backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-cross-namespace-backend",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:      "dummy-backend",
										Namespace: model.AddressOf[gatewayv1.Namespace]("another-namespace"),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with cross namespace backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-cross-namespace-backend-with-grant",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:      "dummy-backend-grant",
										Namespace: model.AddressOf[gatewayv1.Namespace]("another-namespace"),
										Port:      model.AddressOf[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// ReferenceGrant to allow "http-route-with-cross-namespace-backend-with-grant
		&gatewayv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-service-from-default",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1beta1.ReferenceGrantSpec{
				From: []gatewayv1beta1.ReferenceGrantFrom{
					{
						Group:     "gateway.networking.k8s.io",
						Kind:      "HTTPRoute",
						Namespace: "default",
					},
				},
				To: []gatewayv1beta1.ReferenceGrantTo{
					{
						Group: "",
						Kind:  "Service",
						Name:  ObjectNamePtr("dummy-backend-grant"),
					},
				},
			},
		},

		// HTTPRoute with unsupported backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-unsupported-backend",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
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
		// HTTPRoute missing port for backend Service
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-missing-port-for-backend-Service",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:  "missing-port-service-backend",
										Group: GroupPtr(""),
										Kind:  KindPtr("Service"),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with non-existent gateway
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "non-existent-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: model.AddressOf[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with valid but not allowed gateway
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-not-allowed-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name:      "dummy-gateway",
							Namespace: model.AddressOf[gatewayv1.Namespace]("another-namespace"),
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: model.AddressOf[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with non-matching hostname with gateway listener
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-non-matching-hostname",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Hostnames: []gatewayv1.Hostname{
					"non-matching-hostname",
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: model.AddressOf[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
	}
)

func Test_httpRouteReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(httpRouteFixture...).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		Build()
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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)

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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, "BackendNotFound", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)

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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "InvalidHTTPRoute", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "NotAllowedByListeners", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "HTTPRoute is not allowed to attach to this Gateway due to namespace restrictions", route.Status.RouteStatus.Parents[0].Conditions[0].Message)

		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)
		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "NoMatchingListenerHostname", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "No matching listener hostname", route.Status.RouteStatus.Parents[0].Conditions[0].Message)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		require.Equal(t, "RefNotPermitted", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
		require.Equal(t, "Cross namespace references are not allowed", route.Status.RouteStatus.Parents[0].Conditions[1].Message)
	})

	t.Run("http route with cross namespace backend with reference grant", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-cross-namespace-backend-with-grant",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
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

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		require.Equal(t, "InvalidKind", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
		require.Equal(t, "Unsupported backend kind UnsupportedKind", route.Status.RouteStatus.Parents[0].Conditions[1].Message)
	})

	t.Run("http route missing port of Service backend", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-missing-port-for-backend-Service",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		require.Equal(t, "InvalidKind", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
		require.Equal(t, "Must have port for Service reference", route.Status.RouteStatus.Parents[0].Conditions[1].Message)
	})
}
