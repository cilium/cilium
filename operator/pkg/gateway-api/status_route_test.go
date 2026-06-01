// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
)

func TestPruneRouteParentStatusesPrunesDetachedParents(t *testing.T) {
	currentParent := gatewayv1.ParentReference{
		Name: "current-gateway",
	}
	detachedParent := gatewayv1.ParentReference{
		Name: "detached-gateway",
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route",
			Namespace:  "default",
			Generation: 7,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{currentParent},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef:      detachedParent,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{{
							Type:   string(gatewayv1.RouteConditionAccepted),
							Status: metav1.ConditionFalse,
							Reason: string(gatewayv1.RouteReasonNotAllowedByListeners),
						}},
					},
					{
						ParentRef:      currentParent,
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

	require.Len(t, route.Status.Parents, 2)
	require.Equal(t, detachedParent, route.Status.Parents[0].ParentRef)
	require.Equal(t, currentParent, route.Status.Parents[1].ParentRef)

	input.SetAllParentCondition(metav1.Condition{
		Type:   string(gatewayv1.RouteConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonAccepted),
	})

	require.Len(t, route.Status.Parents, 2)
	require.Equal(t, detachedParent, route.Status.Parents[0].ParentRef)
	require.Equal(t, currentParent, route.Status.Parents[1].ParentRef)

	route.Status.Parents = pruneRouteParentStatuses(route.Status.Parents, route.Spec.ParentRefs)

	require.Len(t, route.Status.Parents, 1)
	require.Equal(t, currentParent, route.Status.Parents[0].ParentRef)
}
