// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestParentStatusIsScopedToController(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute"} {
		for _, controllers := range [][2]string{
			{"example.com/controller-a", "example.com/controller-b"},
			{"example.com/controller-b", "example.com/controller-a"},
		} {
			t.Run(kind+"/"+controllers[1], func(t *testing.T) {
				parent := gatewayv1.ParentReference{Name: "gateway"}
				original := gatewayv1.RouteParentStatus{
					ParentRef: parent, ControllerName: gatewayv1.GatewayController(controllers[0]),
					Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: 1, LastTransitionTime: metav1.Now()}},
				}
				status := gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{*original.DeepCopy()}}
				var set func(gatewayv1.ParentReference, metav1.Condition)
				var current *gatewayv1.RouteStatus
				switch kind {
				case "HTTPRoute":
					r := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Status: gatewayv1.HTTPRouteStatus{RouteStatus: status}}
					set = (&HTTPRouteInput{HTTPRoute: r, ControllerName: controllers[1]}).SetParentCondition
					current = &r.Status.RouteStatus
				case "GRPCRoute":
					r := &gatewayv1.GRPCRoute{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Status: gatewayv1.GRPCRouteStatus{RouteStatus: status}}
					set = (&GRPCRouteInput{GRPCRoute: r, ControllerName: controllers[1]}).SetParentCondition
					current = &r.Status.RouteStatus
				case "TLSRoute":
					r := &gatewayv1.TLSRoute{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Status: gatewayv1.TLSRouteStatus{RouteStatus: status}}
					set = (&TLSRouteInput{TLSRoute: r, ControllerName: controllers[1]}).SetParentCondition
					current = &r.Status.RouteStatus
				case "TCPRoute":
					r := &gatewayv1.TCPRoute{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Status: gatewayv1.TCPRouteStatus{RouteStatus: status}}
					set = (&TCPRouteInput{TCPRoute: r, ControllerName: controllers[1]}).SetParentCondition
					current = &r.Status.RouteStatus
				case "UDPRoute":
					r := &gatewayv1.UDPRoute{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Status: gatewayv1.UDPRouteStatus{RouteStatus: status}}
					set = (&UDPRouteInput{UDPRoute: r, ControllerName: controllers[1]}).SetParentCondition
					current = &r.Status.RouteStatus
				}
				set(parent, metav1.Condition{Type: "Accepted", Status: metav1.ConditionFalse, Reason: "NotAllowedByListeners"})
				set(parent, metav1.Condition{Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted"})
				checkControllerStatuses(t, *current, original, controllers[1])
			})
		}
	}
}

func checkControllerStatuses(t *testing.T, status gatewayv1.RouteStatus, original gatewayv1.RouteParentStatus, controller string) {
	t.Helper()
	require.Len(t, status.Parents, 2)
	require.Equal(t, original, status.Parents[0], "another controller's status must be preserved")
	current := status.Parents[1]
	require.Equal(t, gatewayv1.GatewayController(controller), current.ControllerName)
	require.Equal(t, original.ParentRef, current.ParentRef)
	require.Len(t, current.Conditions, 1)
	require.Equal(t, int64(2), current.Conditions[0].ObservedGeneration)
	require.Equal(t, metav1.ConditionTrue, current.Conditions[0].Status)
}
