// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
)

func TestPruneRouteParentStatuses(t *testing.T) {
	// currentParentSpec and currentParentStatus have identical values but distinct
	// pointer instances, simulating spec vs status after an APIServer round-trip.
	currentParentSpec := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      "current-gateway",
	}
	currentParentStatus := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      "current-gateway",
	}
	ourDetachedParent := gatewayv1.ParentReference{
		Name: "detached-gateway",
	}
	otherControllerDetachedParent := gatewayv1.ParentReference{
		Name: "other-controller-gateway",
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route",
			Namespace:  "default",
			Generation: 7,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{currentParentSpec},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef:      ourDetachedParent,
						ControllerName: defaultControllerName,
						Conditions: []metav1.Condition{{
							Type:   string(gatewayv1.RouteConditionAccepted),
							Status: metav1.ConditionFalse,
							Reason: string(gatewayv1.RouteReasonNotAllowedByListeners),
						}},
					},
					{
						ParentRef:      otherControllerDetachedParent,
						ControllerName: gatewayv1.GatewayController("example.com/other-gateway-controller"),
					},
					{
						ParentRef:      currentParentStatus,
						ControllerName: defaultControllerName,
						Conditions: []metav1.Condition{{
							Type:   string(gatewayv1.RouteConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: string(gatewayv1.RouteReasonAccepted),
						}},
					},
				},
			},
		},
	}

	input := &routechecks.HTTPRouteInput{HTTPRoute: route}

	require.Len(t, route.Status.Parents, 3)
	require.Equal(t, ourDetachedParent, route.Status.Parents[0].ParentRef)
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[1].ParentRef)
	require.Equal(t, currentParentStatus, route.Status.Parents[2].ParentRef)

	acceptedCond := metav1.Condition{
		Type:               string(gatewayv1.RouteConditionAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.RouteReasonAccepted),
		ObservedGeneration: input.HTTPRoute.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	for _, parent := range input.HTTPRoute.Spec.ParentRefs {
		input.SetParentCondition(parent, acceptedCond)
	}

	require.Len(t, route.Status.Parents, 3, "merge alone keeps both detached statuses")
	require.Equal(t, ourDetachedParent, route.Status.Parents[0].ParentRef, "merge alone keeps both detached statuses")
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[1].ParentRef, "merge alone keeps both detached statuses")
	require.Equal(t, currentParentStatus, route.Status.Parents[2].ParentRef, "merge alone keeps both detached statuses")

	route.Status.Parents = pruneRouteParentStatuses(route.Status.Parents, route.Spec.ParentRefs, defaultControllerName)

	require.Len(t, route.Status.Parents, 2, "prune removes only the detached Cilium-owned status")
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[0].ParentRef, "prune removes only the detached Cilium-owned status")
	require.Equal(t, gatewayv1.GatewayController("example.com/other-gateway-controller"), route.Status.Parents[0].ControllerName, "prune removes only the detached Cilium-owned status")
	require.Equal(t, currentParentStatus, route.Status.Parents[1].ParentRef, "prune removes only the detached Cilium-owned status")
	require.Equal(t, gatewayv1.GatewayController(defaultControllerName), route.Status.Parents[1].ControllerName, "prune removes only the detached Cilium-owned status")
}

func TestSetTCPRouteStatusesPrunesDetachedParents(t *testing.T) {
	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Status: gatewayv1.TCPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
			ParentRef:      gatewayv1.ParentReference{Name: "detached-gateway"},
			ControllerName: gatewayv1.GatewayController(defaultControllerName),
		}}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithStatusSubresource(&gatewayv1.TCPRoute{}).
		WithObjects(route).
		Build()
	routes := &gatewayv1.TCPRouteList{}
	require.NoError(t, c.List(t.Context(), routes))

	r := &gatewayReconciler{Client: c, controllerName: defaultControllerName}
	require.NoError(t, r.setTCPRouteStatuses(slog.Default(), t.Context(), routes, &gatewayv1.ReferenceGrantList{}))

	updated := &gatewayv1.TCPRoute{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), updated))
	require.Empty(t, updated.Status.Parents)
}

func TestSetUDPRouteStatusesPrunesDetachedParents(t *testing.T) {
	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Status: gatewayv1.UDPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
			ParentRef:      gatewayv1.ParentReference{Name: "detached-gateway"},
			ControllerName: gatewayv1.GatewayController(defaultControllerName),
		}}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithStatusSubresource(&gatewayv1.UDPRoute{}).
		WithObjects(route).
		Build()
	routes := &gatewayv1.UDPRouteList{}
	require.NoError(t, c.List(t.Context(), routes))

	r := &gatewayReconciler{Client: c, controllerName: defaultControllerName}
	require.NoError(t, r.setUDPRouteStatuses(slog.Default(), t.Context(), routes, &gatewayv1.ReferenceGrantList{}))

	updated := &gatewayv1.UDPRoute{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), updated))
	require.Empty(t, updated.Status.Parents)
}
