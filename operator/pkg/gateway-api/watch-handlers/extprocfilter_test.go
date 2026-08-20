// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestEnqueueRequestForExtProcFilter(t *testing.T) {
	scheme := helpers.TestScheme(nil)

	filter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "referenced-filter",
			Namespace: "default",
		},
	}

	unreferencedFilter := &v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unreferenced-filter",
			Namespace: "default",
		},
	}

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(testGatewayControllerName),
		},
	}

	otherGatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "some-other-controller",
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
		},
	}

	otherControllerGw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "other",
		},
	}

	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "http-gateway"}},
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

	otherControllerRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-controller-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "other-gateway"}},
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
		WithObjects(filter, unreferencedFilter, gatewayClass, otherGatewayClass, gw, otherControllerGw, httpRoute, otherControllerRoute).
		WithIndex(&gatewayv1.Gateway{}, indexers.ImplementationGatewayIndex, func(rawObj client.Object) []string {
			gw := rawObj.(*gatewayv1.Gateway)
			if string(gw.Spec.GatewayClassName) == "cilium" {
				return []string{testGatewayControllerName}
			}
			return nil
		}).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.ExtProcFilterHTTPRouteIndex, indexers.IndexHTTPRouteByExtProcFilter).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.ExtProcFilterGRPCRouteIndex, func(rawObj client.Object) []string {
			return nil
		}).
		Build()

	handler := EnqueueRequestForExtProcFilter(fakeClient, hivetest.Logger(t), testGatewayControllerName)

	t.Run("referenced filter enqueues only its route's Gateway", func(t *testing.T) {
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
			{Namespace: "default", Name: "http-gateway"},
		}, got)
	})

	t.Run("unreferenced filter enqueues nothing", func(t *testing.T) {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: unreferencedFilter}, queue)

		require.Equal(t, 0, queue.Len())
	})
}
