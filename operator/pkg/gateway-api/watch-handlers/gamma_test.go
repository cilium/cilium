// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// TestEnqueueRequestForGAMMAHTTPRouteOnlyMatchesServiceParents ensures that only
// core Service parents resolve to a GAMMA Service. Any other parent kind sharing
// a name with a Service in the same namespace must not enqueue that Service.
func TestEnqueueRequestForGAMMAHTTPRouteOnlyMatchesServiceParents(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	// A valid GAMMA Service whose name collides with the ListenerSet and the
	// Gateway referenced as parents below.
	gammaService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-name",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}

	serviceParent := func(name string) gatewayv1.ParentReference {
		return gatewayv1.ParentReference{
			Group: ptr.To[gatewayv1.Group](corev1.GroupName),
			Kind:  ptr.To[gatewayv1.Kind]("Service"),
			Name:  gatewayv1.ObjectName(name),
		}
	}

	tests := []struct {
		name   string
		parent gatewayv1.ParentReference
		want   []types.NamespacedName
	}{
		{
			name:   "core Service parent enqueues the GAMMA Service",
			parent: serviceParent("shared-name"),
			want:   []types.NamespacedName{{Namespace: "default", Name: "shared-name"}},
		},
		{
			name: "ListenerSet parent does not enqueue a same-named Service",
			parent: gatewayv1.ParentReference{
				Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
				Kind:  ptr.To[gatewayv1.Kind]("ListenerSet"),
				Name:  "shared-name",
			},
		},
		{
			name: "Gateway parent does not enqueue a same-named Service",
			parent: gatewayv1.ParentReference{
				Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
				Kind:  ptr.To[gatewayv1.Kind]("Gateway"),
				Name:  "shared-name",
			},
		},
		{
			name: "unrelated parent kind does not enqueue a same-named Service",
			parent: gatewayv1.ParentReference{
				Group: ptr.To[gatewayv1.Group]("example.com"),
				Kind:  ptr.To[gatewayv1.Kind]("SomeOtherKind"),
				Name:  "shared-name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{tt.parent},
					},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(gammaService, route).
				Build()

			handler := EnqueueRequestForGAMMAHTTPRoute(fakeClient, hivetest.Logger(t))
			queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
			defer queue.ShutDown()

			handler.Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: route}, queue)

			var got []types.NamespacedName
			for queue.Len() > 0 {
				item, shutdown := queue.Get()
				require.False(t, shutdown)
				got = append(got, item.NamespacedName)
				queue.Done(item)
			}

			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestEnqueueRequestForExtProcFilterGAMMA(t *testing.T) {
	scheme := helpers.TestScheme(nil)

	filter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "referenced-filter",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{BackendRef: v2alpha1.ExtProcBackendRef{
			Name: "ext-proc-backend",
			Port: 4317,
		}},
	}

	unreferencedFilter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unreferenced-filter",
			Namespace: "gateway-conformance-mesh",
		},
	}

	nonServiceParentFilter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-service-parent-filter",
			Namespace: "gateway-conformance-mesh",
		},
	}

	grpcFilter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-filter",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{BackendRef: v2alpha1.ExtProcBackendRef{
			Name: "ext-proc-backend",
			Port: 4317,
		}},
	}

	httpGammaService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-echo",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}
	grpcGammaService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-echo",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}
	backendService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ext-proc-backend",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 4317}}},
	}

	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mesh-route",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Group: ptr.To[gatewayv1.Group](""),
						Kind:  ptr.To[gatewayv1.Kind]("Service"),
						Name:  "http-echo",
					},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterExtensionRef,
							ExtensionRef: &gatewayv1.LocalObjectReference{
								Group: "cilium.io",
								Kind:  "CiliumEnvoyExtProcFilter",
								Name:  "referenced-filter",
							},
						},
					},
				},
			},
		},
	}

	// This route's arbitrary parent deliberately collides with httpGammaService. It
	// must not be treated as a Service parent just because a Service exists with
	// the same name and namespace.
	nonServiceParentRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-service-parent-route",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Group: ptr.To[gatewayv1.Group]("example.io"),
						Kind:  ptr.To[gatewayv1.Kind]("OtherParent"),
						Name:  "http-echo",
					},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterExtensionRef,
							ExtensionRef: &gatewayv1.LocalObjectReference{
								Group: "cilium.io",
								Kind:  "CiliumEnvoyExtProcFilter",
								Name:  "non-service-parent-filter",
							},
						},
					},
				},
			},
		},
	}

	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-route",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Group: ptr.To[gatewayv1.Group](""),
						Kind:  ptr.To[gatewayv1.Kind]("Service"),
						Name:  "grpc-echo",
					},
				},
			},
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterExtensionRef,
							ExtensionRef: &gatewayv1.LocalObjectReference{
								Group: "cilium.io",
								Kind:  "CiliumEnvoyExtProcFilter",
								Name:  "grpc-filter",
							},
						},
					},
				},
			},
		},
	}

	// A route whose parent is a Gateway (not GAMMA) that also references the
	// filter; getGammaReconcileRequestsForRoute accepts only Service parents, so
	// this must not contribute any reconcile.Request.
	gatewayParentedRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-route",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "some-gateway"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterExtensionRef,
							ExtensionRef: &gatewayv1.LocalObjectReference{
								Group: "cilium.io",
								Kind:  "CiliumEnvoyExtProcFilter",
								Name:  "referenced-filter",
							},
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(filter, unreferencedFilter, nonServiceParentFilter, grpcFilter, httpGammaService, grpcGammaService, backendService, httpRoute, nonServiceParentRoute, grpcRoute, gatewayParentedRoute).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.ExtProcFilterHTTPRouteIndex, indexers.IndexHTTPRouteByExtProcFilter).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.ExtProcFilterGRPCRouteIndex, indexers.IndexGRPCRouteByExtProcFilter).
		Build()

	handler := EnqueueRequestForExtProcFilterGAMMA(fakeClient, hivetest.Logger(t))

	t.Run("referenced filter enqueues only its route's GAMMA Service", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: filter}, queue)

		var got []types.NamespacedName
		for queue.Len() > 0 {
			item, shutdown := queue.Get()
			require.False(t, shutdown)
			got = append(got, item.NamespacedName)
			queue.Done(item)
		}

		require.ElementsMatch(t, []types.NamespacedName{
			{Namespace: "gateway-conformance-mesh", Name: "http-echo"},
		}, got)
	})

	t.Run("non-Service parent does not enqueue a colliding Service", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: nonServiceParentFilter}, queue)

		require.Equal(t, 0, queue.Len())
	})

	t.Run("GRPCRoute Service parent enqueues its GAMMA Service", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: grpcFilter}, queue)

		var got []types.NamespacedName
		for queue.Len() > 0 {
			item, shutdown := queue.Get()
			require.False(t, shutdown)
			got = append(got, item.NamespacedName)
			queue.Done(item)
		}

		require.ElementsMatch(t, []types.NamespacedName{
			{Namespace: "gateway-conformance-mesh", Name: "grpc-echo"},
		}, got)
	})

	t.Run("unreferenced filter enqueues nothing", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: unreferencedFilter}, queue)

		require.Equal(t, 0, queue.Len())
	})

	t.Run("backend Service enqueues each GAMMA parent and not the backend itself", func(t *testing.T) {
		backendHandler := EnqueueRequestForExtProcFilterBackendServiceGAMMA(fakeClient, hivetest.Logger(t))
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		backendHandler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: backendService}, queue)

		var got []types.NamespacedName
		for queue.Len() > 0 {
			item, shutdown := queue.Get()
			require.False(t, shutdown)
			got = append(got, item.NamespacedName)
			queue.Done(item)
		}
		require.ElementsMatch(t, []types.NamespacedName{
			{Namespace: "gateway-conformance-mesh", Name: "http-echo"},
			{Namespace: "gateway-conformance-mesh", Name: "grpc-echo"},
		}, got)

		queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()
		backendHandler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: httpGammaService}, queue)
		require.Equal(t, 0, queue.Len())
	})
}
