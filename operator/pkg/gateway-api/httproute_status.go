// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

const (
	httpRouteAcceptedMessage = "Accepted HTTPRoute"
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

func httpBackendNotFoundRouteCondition(hr *gatewayv1beta1.HTTPRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1beta1.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1beta1.RouteReasonBackendNotFound),
		Message:            msg,
		ObservedGeneration: hr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func httpNoMatchingListenerPortCondition(hr *gatewayv1beta1.HTTPRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1beta1.RouteConditionAccepted),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1beta1.RouteReasonNoMatchingParent),
		Message:            msg,
		ObservedGeneration: hr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func httpNoMatchingListenerHostnameRouteCondition(hr *gatewayv1beta1.HTTPRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1beta1.RouteConditionAccepted),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1beta1.RouteReasonNoMatchingListenerHostname),
		Message:            msg,
		ObservedGeneration: hr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func httpRefNotPermittedRouteCondition(hr *gatewayv1beta1.HTTPRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonRefNotPermitted),
		Message:            msg,
		ObservedGeneration: hr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func httpInvalidKindRouteCondition(hr *gatewayv1beta1.HTTPRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonInvalidKind),
		Message:            msg,
		ObservedGeneration: hr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func mergeHTTPRouteStatusConditions(hr *gatewayv1beta1.HTTPRoute, parentRef gatewayv1beta1.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range hr.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		hr.Status.RouteStatus.Parents[index].Conditions = merge(hr.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	hr.Status.RouteStatus.Parents = append(hr.Status.RouteStatus.Parents, gatewayv1beta1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}

func httpRouteNotAllowedByListenersCondition(hr *gatewayv1beta1.HTTPRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionAccepted),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonNotAllowedByListeners),
		Message:            msg,
		ObservedGeneration: hr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}
