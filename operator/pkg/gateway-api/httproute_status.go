// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	httpRouteAcceptedMessage = "Valid HTTPRoute"
)

func httpRouteAcceptedCondition(hr *gatewayv1beta1.HTTPRoute, accepted bool, msg string) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               conditionStatusAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonAccepted,
			Message:            msg,
			ObservedGeneration: hr.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               conditionStatusAccepted,
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidHTTPRoute",
			Message:            msg,
			ObservedGeneration: hr.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func mergeHTTPRouteStatusConditions(status *gatewayv1beta1.RouteStatus, parentRef gatewayv1beta1.ParentReference, updates []metav1.Condition) {
	for _, parent := range status.Parents {
		if cmp.Equal(parent.ParentRef, parentRef) {
			parent.Conditions = merge(parent.Conditions, updates...)
			return
		}
	}
	status.Parents = append(status.Parents, gatewayv1beta1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}
