// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
)

func TestBackendRefMatchesInferencePool(t *testing.T) {
	pool := &gateway_inf_ext.InferencePool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "llm-pool",
			Namespace: "default",
		},
	}

	inferencePoolKind := ptr.To(gatewayv1.Kind("InferencePool"))
	serviceKind := ptr.To(gatewayv1.Kind("Service"))
	group := ptr.To(gatewayv1.Group(gateway_inf_ext.GroupName))
	defaultNS := ptr.To(gatewayv1.Namespace("default"))
	otherNS := ptr.To(gatewayv1.Namespace("other-ns"))

	tests := []struct {
		name    string
		ref     gatewayv1.HTTPBackendRef
		routeNs string
		want    bool
	}{
		{
			name: "matches by name, namespace inherited from route",
			ref: gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{
				BackendObjectReference: gatewayv1.BackendObjectReference{
					Kind: inferencePoolKind, Group: group, Name: "llm-pool",
				},
			}},
			routeNs: "default",
			want:    true,
		},
		{
			name: "matches with explicit namespace override",
			ref: gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{
				BackendObjectReference: gatewayv1.BackendObjectReference{
					Kind: inferencePoolKind, Group: group, Name: "llm-pool", Namespace: defaultNS,
				},
			}},
			routeNs: "some-other-route-ns",
			want:    true,
		},
		{
			name: "wrong kind is rejected",
			ref: gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{
				BackendObjectReference: gatewayv1.BackendObjectReference{
					Kind: serviceKind, Group: group, Name: "llm-pool",
				},
			}},
			routeNs: "default",
			want:    false,
		},
		{
			name: "name mismatch is rejected",
			ref: gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{
				BackendObjectReference: gatewayv1.BackendObjectReference{
					Kind: inferencePoolKind, Group: group, Name: "not-the-pool",
				},
			}},
			routeNs: "default",
			want:    false,
		},
		{
			name: "namespace mismatch is rejected",
			ref: gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{
				BackendObjectReference: gatewayv1.BackendObjectReference{
					Kind: inferencePoolKind, Group: group, Name: "llm-pool", Namespace: otherNS,
				},
			}},
			routeNs: "default",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, backendRefMatchesInferencePool(tt.ref, tt.routeNs, pool))
		})
	}
}

func TestGatewayRequestForInferencePool(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	pool := &gateway_inf_ext.InferencePool{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-pool", Namespace: "default"},
	}

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(testGatewayControllerName)},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "cilium"},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "my-gateway"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Kind:  ptr.To(gatewayv1.Kind("InferencePool")),
						Group: ptr.To(gatewayv1.Group(gateway_inf_ext.GroupName)),
						Name:  "llm-pool",
					},
				}}},
			}},
		},
	}

	unrelatedRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "other-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "my-gateway"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{Name: "some-service"},
				}}},
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gatewayClass, gw, route, unrelatedRoute).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.InferencePoolHTTPRouteIndex, indexers.GenerateIndexerHTTPRouteByInferencePool).
		Build()

	reqs := gatewayRequestForInferencePool(t.Context(), fakeClient, pool, hivetest.Logger(t), testGatewayControllerName)

	require.ElementsMatch(t, []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gateway"}},
	}, reqs)
}

func TestGatewayRequestForInferencePool_NoMatchingRoutes(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	pool := &gateway_inf_ext.InferencePool{
		ObjectMeta: metav1.ObjectMeta{Name: "unreferenced-pool", Namespace: "default"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.InferencePoolHTTPRouteIndex, indexers.GenerateIndexerHTTPRouteByInferencePool).
		Build()

	reqs := gatewayRequestForInferencePool(t.Context(), fakeClient, pool, hivetest.Logger(t), testGatewayControllerName)
	require.Empty(t, reqs)
}

func TestEnqueueRequestForOwningInferencePool(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	pool := &gateway_inf_ext.InferencePool{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-pool", Namespace: "default"},
	}
	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(testGatewayControllerName)},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "cilium"},
	}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "my-gateway"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Kind:  ptr.To(gatewayv1.Kind("InferencePool")),
						Group: ptr.To(gatewayv1.Group(gateway_inf_ext.GroupName)),
						Name:  "llm-pool",
					},
				}}},
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gatewayClass, gw, route).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.InferencePoolHTTPRouteIndex, indexers.GenerateIndexerHTTPRouteByInferencePool).
		Build()

	handler := EnqueueRequestForOwningInferencePool(fakeClient, hivetest.Logger(t), testGatewayControllerName)
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer queue.ShutDown()

	handler.Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: pool}, queue)

	require.Equal(t, 1, queue.Len())
	item, shutdown := queue.Get()
	require.False(t, shutdown)
	require.Equal(t, types.NamespacedName{Namespace: "default", Name: "my-gateway"}, item.NamespacedName)
}

func TestEnqueueRequestForOwningInferencePool_WrongType(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	handler := EnqueueRequestForOwningInferencePool(fakeClient, hivetest.Logger(t), testGatewayControllerName)
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer queue.ShutDown()

	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "not-a-pool", Namespace: "default"}}
	handler.Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: svc}, queue)

	require.Equal(t, 0, queue.Len())
}

func TestEnqueueRequestForOwningEndpointSlice(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(testGatewayControllerName)},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "cilium"},
	}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "my-gateway"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Kind:  ptr.To(gatewayv1.Kind("InferencePool")),
						Group: ptr.To(gatewayv1.Group(gateway_inf_ext.GroupName)),
						Name:  "llm-pool",
					},
				}}},
			}},
		},
	}

	shadowSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "llm-pool-shadow-service",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: gateway_inf_ext.GroupVersion.String(),
				Kind:       "InferencePool",
				Name:       "llm-pool",
				UID:        types.UID("test-uid"),
				Controller: ptr.To(true),
			}},
		},
	}

	unrelatedSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-service", Namespace: "default"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gatewayClass, gw, route, shadowSvc, unrelatedSvc).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.InferencePoolHTTPRouteIndex, indexers.GenerateIndexerHTTPRouteByInferencePool).
		Build()

	handler := EnqueueRequestForOwningEndpointSlice(fakeClient, hivetest.Logger(t), testGatewayControllerName)

	drain := func(obj client.Object) []types.NamespacedName {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer queue.ShutDown()
		handler.Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: obj}, queue)

		var got []types.NamespacedName
		for queue.Len() > 0 {
			item, shutdown := queue.Get()
			require.False(t, shutdown)
			got = append(got, item.NamespacedName)
			queue.Done(item)
		}
		return got
	}

	t.Run("missing service-name label returns nothing", func(t *testing.T) {
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Name: "eps-no-label", Namespace: "default"},
		}
		require.Empty(t, drain(eps))
	})

	t.Run("service-name label points at a service that does not exist", func(t *testing.T) {
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "eps-missing-svc",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "does-not-exist"},
			},
		}
		require.Empty(t, drain(eps))
	})

	t.Run("owning service has no InferencePool owner ref", func(t *testing.T) {
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "eps-unrelated",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: unrelatedSvc.Name},
			},
		}
		require.Empty(t, drain(eps))
	})

	t.Run("owning service is an InferencePool shadow service", func(t *testing.T) {
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "eps-shadow",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: shadowSvc.Name},
			},
		}
		require.Equal(t, []types.NamespacedName{{Namespace: "default", Name: "my-gateway"}}, drain(eps))
	})
}
