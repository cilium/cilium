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

	// A route whose parent is a Gateway (not GAMMA) that also references the
	// filter; getGammaReconcileRequestsForRoute skips Gateway parents, so this
	// must not contribute any reconcile.Request.
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
		WithObjects(filter, unreferencedFilter, gammaService, httpRoute, gatewayParentedRoute).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.ExtProcFilterHTTPRouteIndex, indexers.IndexHTTPRouteByExtProcFilter).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.ExtProcFilterGRPCRouteIndex, func(rawObj client.Object) []string {
			return nil
		}).
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

	t.Run("unreferenced filter enqueues nothing", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: unreferencedFilter}, queue)

		require.Equal(t, 0, queue.Len())
	})
}
