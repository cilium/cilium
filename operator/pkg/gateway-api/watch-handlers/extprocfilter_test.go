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

func TestEnqueueRequestForExtProcFilter(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	newFilter := func(name string) *v2alpha1.CiliumEnvoyExtProcFilter {
		return &v2alpha1.CiliumEnvoyExtProcFilter{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		}
	}
	newHTTPRoute := func(name, filterName string, parents ...gatewayv1.ParentReference) *gatewayv1.HTTPRoute {
		return &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parents},
				Rules: []gatewayv1.HTTPRouteRule{{Filters: []gatewayv1.HTTPRouteFilter{{
					Type: gatewayv1.HTTPRouteFilterExtensionRef,
					ExtensionRef: &gatewayv1.LocalObjectReference{
						Group: "cilium.io",
						Kind:  "CiliumEnvoyExtProcFilter",
						Name:  gatewayv1.ObjectName(filterName),
					},
				}}}},
			},
		}
	}
	newGRPCRoute := func(name, filterName string, parents ...gatewayv1.ParentReference) *gatewayv1.GRPCRoute {
		return &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parents},
				Rules: []gatewayv1.GRPCRouteRule{{Filters: []gatewayv1.GRPCRouteFilter{{
					Type: gatewayv1.GRPCRouteFilterExtensionRef,
					ExtensionRef: &gatewayv1.LocalObjectReference{
						Group: "cilium.io",
						Kind:  "CiliumEnvoyExtProcFilter",
						Name:  gatewayv1.ObjectName(filterName),
					},
				}}}},
			},
		}
	}

	filter := newFilter("referenced-filter")
	unreferencedFilter := newFilter("unreferenced-filter")
	httpOnlyFilter := newFilter("http-only-filter")
	grpcOnlyFilter := newFilter("grpc-only-filter")
	listenerSetOnlyFilter := newFilter("listenerset-only-filter")

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

	httpRoute := newHTTPRoute(
		"http-route", "referenced-filter",
		gatewayv1.ParentReference{Name: "http-gateway"},
		gatewayv1.ParentReference{Kind: ptr.To[gatewayv1.Kind]("ListenerSet"), Name: "http-listeners"},
	)

	grpcRoute := newGRPCRoute(
		"grpc-route", "referenced-filter",
		gatewayv1.ParentReference{Name: "http-gateway"},
	)

	httpOnlyRoute := newHTTPRoute(
		"http-only-route", "http-only-filter",
		gatewayv1.ParentReference{Name: "http-gateway"},
	)

	grpcOnlyRoute := newGRPCRoute(
		"grpc-only-route", "grpc-only-filter",
		gatewayv1.ParentReference{Name: "http-gateway"},
	)

	listenerSetOnlyRoute := newHTTPRoute(
		"listenerset-only-route", "listenerset-only-filter",
		gatewayv1.ParentReference{Kind: ptr.To[gatewayv1.Kind]("ListenerSet"), Name: "http-listeners"},
	)

	listenerSet := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-listeners",
			Namespace: "default",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "http-gateway"},
		},
	}

	otherControllerRoute := newHTTPRoute(
		"other-controller-route", "referenced-filter",
		gatewayv1.ParentReference{Name: "other-gateway"},
	)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			filter, unreferencedFilter, httpOnlyFilter, grpcOnlyFilter, listenerSetOnlyFilter,
			gatewayClass, otherGatewayClass, gw, otherControllerGw, listenerSet,
			httpRoute, grpcRoute, httpOnlyRoute, grpcOnlyRoute, listenerSetOnlyRoute, otherControllerRoute,
		).
		// Simulate a Gateway that was indexed before its GatewayClass existed.
		WithIndex(&gatewayv1.Gateway{}, indexers.ImplementationGatewayIndex, func(client.Object) []string {
			return nil
		}).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.ExtProcFilterHTTPRouteIndex, indexers.IndexHTTPRouteByExtProcFilter).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.ExtProcFilterGRPCRouteIndex, indexers.IndexGRPCRouteByExtProcFilter).
		Build()

	handler := EnqueueRequestForExtProcFilter(fakeClient, hivetest.Logger(t), testGatewayControllerName)
	enqueue := func(t *testing.T, extProcFilter *v2alpha1.CiliumEnvoyExtProcFilter) []types.NamespacedName {
		t.Helper()
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()

		handler.Update(t.Context(), event.TypedUpdateEvent[client.Object]{ObjectNew: extProcFilter}, queue)

		var got []types.NamespacedName
		for queue.Len() > 0 {
			item, shutdown := queue.Get()
			require.False(t, shutdown)
			got = append(got, item.NamespacedName)
			queue.Done(item)
		}
		return got
	}
	wantGateway := []types.NamespacedName{{Namespace: "default", Name: "http-gateway"}}

	t.Run("combined route parents enqueue the Gateway once", func(t *testing.T) {
		require.ElementsMatch(t, wantGateway, enqueue(t, filter))
	})

	t.Run("HTTPRoute parent enqueues the Gateway without the implementation index", func(t *testing.T) {
		require.ElementsMatch(t, wantGateway, enqueue(t, httpOnlyFilter))
	})

	t.Run("GRPCRoute parent enqueues the Gateway", func(t *testing.T) {
		require.ElementsMatch(t, wantGateway, enqueue(t, grpcOnlyFilter))
	})

	t.Run("ListenerSet parent enqueues its Gateway", func(t *testing.T) {
		require.ElementsMatch(t, wantGateway, enqueue(t, listenerSetOnlyFilter))
	})

	t.Run("unreferenced filter enqueues nothing", func(t *testing.T) {
		require.Empty(t, enqueue(t, unreferencedFilter))
	})
}
