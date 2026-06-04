// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestHTTPRouteInput_MergeStatusConditions(t *testing.T) {
	// 1. Create a parentRef that will be in the route status
	parentInStatus := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("my-gateway"),
	}

	// 2. Create the route with this parent in its status
	route := &gatewayv1.HTTPRoute{
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef:      parentInStatus,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: metav1.ConditionFalse,
								Reason: "InitialReason",
							},
						},
					},
				},
			},
		},
	}

	input := &HTTPRouteInput{
		Ctx:       context.Background(),
		Logger:    slog.Default(),
		HTTPRoute: route,
	}

	// 3. Create a parentRef with identical values but different pointer instances to merge into status
	parentToMerge := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("my-gateway"),
	}

	newCondition := metav1.Condition{
		Type:   "Accepted",
		Status: metav1.ConditionTrue,
		Reason: "MergedReason",
	}

	// 4. Run SetParentCondition which internally calls mergeStatusConditions
	input.SetParentCondition(parentToMerge, newCondition)

	// 5. Verify that:
	// - The parent entry is not duplicated (still only 1 parent entry in status)
	// - The existing condition was merged/updated with the new condition
	assert.Len(t, route.Status.RouteStatus.Parents, 1)
	assert.Equal(t, parentInStatus.Name, route.Status.RouteStatus.Parents[0].ParentRef.Name)
	assert.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, route.Status.RouteStatus.Parents[0].Conditions[0].Status)
	assert.Equal(t, "MergedReason", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
}

func TestGRPCRouteInput_MergeStatusConditions(t *testing.T) {
	parentInStatus := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("my-gateway"),
	}

	route := &gatewayv1.GRPCRoute{
		Status: gatewayv1.GRPCRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef:      parentInStatus,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: metav1.ConditionFalse,
								Reason: "InitialReason",
							},
						},
					},
				},
			},
		},
	}

	input := &GRPCRouteInput{
		Ctx:       context.Background(),
		Logger:    slog.Default(),
		GRPCRoute: route,
	}

	parentToMerge := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("my-gateway"),
	}

	newCondition := metav1.Condition{
		Type:   "Accepted",
		Status: metav1.ConditionTrue,
		Reason: "MergedReason",
	}

	input.SetParentCondition(parentToMerge, newCondition)

	assert.Len(t, route.Status.RouteStatus.Parents, 1)
	assert.Equal(t, parentInStatus.Name, route.Status.RouteStatus.Parents[0].ParentRef.Name)
	assert.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, route.Status.RouteStatus.Parents[0].Conditions[0].Status)
	assert.Equal(t, "MergedReason", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
}

func TestTLSRouteInput_MergeStatusConditions(t *testing.T) {
	parentInStatus := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("my-gateway"),
	}

	route := &gatewayv1.TLSRoute{
		Status: gatewayv1.TLSRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef:      parentInStatus,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: metav1.ConditionFalse,
								Reason: "InitialReason",
							},
						},
					},
				},
			},
		},
	}

	input := &TLSRouteInput{
		Ctx:      context.Background(),
		Logger:   slog.Default(),
		TLSRoute: route,
	}

	parentToMerge := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("my-gateway"),
	}

	newCondition := metav1.Condition{
		Type:   "Accepted",
		Status: metav1.ConditionTrue,
		Reason: "MergedReason",
	}

	input.SetParentCondition(parentToMerge, newCondition)

	assert.Len(t, route.Status.RouteStatus.Parents, 1)
	assert.Equal(t, parentInStatus.Name, route.Status.RouteStatus.Parents[0].ParentRef.Name)
	assert.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, route.Status.RouteStatus.Parents[0].Conditions[0].Status)
	assert.Equal(t, "MergedReason", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
}
