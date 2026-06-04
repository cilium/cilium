// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

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
						ControllerName: controllerName,
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
						ControllerName: controllerName,
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

	input.SetAllParentCondition(metav1.Condition{
		Type:   string(gatewayv1.RouteConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonAccepted),
	})

	require.Len(t, route.Status.Parents, 3, "merge alone keeps both detached statuses")
	require.Equal(t, ourDetachedParent, route.Status.Parents[0].ParentRef, "merge alone keeps both detached statuses")
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[1].ParentRef, "merge alone keeps both detached statuses")
	require.Equal(t, currentParentStatus, route.Status.Parents[2].ParentRef, "merge alone keeps both detached statuses")

	route.Status.Parents = pruneRouteParentStatuses(route.Status.Parents, route.Spec.ParentRefs)

	require.Len(t, route.Status.Parents, 2, "prune removes only the detached Cilium-owned status")
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[0].ParentRef, "prune removes only the detached Cilium-owned status")
	require.Equal(t, gatewayv1.GatewayController("example.com/other-gateway-controller"), route.Status.Parents[0].ControllerName, "prune removes only the detached Cilium-owned status")
	require.Equal(t, currentParentStatus, route.Status.Parents[1].ParentRef, "prune removes only the detached Cilium-owned status")
	require.Equal(t, gatewayv1.GatewayController(controllerName), route.Status.Parents[1].ControllerName, "prune removes only the detached Cilium-owned status")
}
