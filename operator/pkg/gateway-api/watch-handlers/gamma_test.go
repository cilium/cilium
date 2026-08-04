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

func TestEnqueueRequestForExtProcFilterGAMMA(t *testing.T) {
	scheme := helpers.TestScheme(nil)

	filter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "referenced-filter",
			Namespace: "gateway-conformance-mesh",
		},
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
	}

	gammaService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo",
			Namespace: "gateway-conformance-mesh",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
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
						Name:  "echo",
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

	// This route's arbitrary parent deliberately collides with gammaService. It
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
						Name:  "echo",
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
						Name:  "echo",
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
		WithObjects(filter, unreferencedFilter, nonServiceParentFilter, grpcFilter, gammaService, httpRoute, nonServiceParentRoute, grpcRoute, gatewayParentedRoute).
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
			{Namespace: "gateway-conformance-mesh", Name: "echo"},
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
			{Namespace: "gateway-conformance-mesh", Name: "echo"},
		}, got)
	})

	t.Run("unreferenced filter enqueues nothing", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: unreferencedFilter}, queue)

		require.Equal(t, 0, queue.Len())
	})
}
