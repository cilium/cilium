// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

const (
	tlsRouteAcceptedMessage = "Accepted TLSRoute"
)

// NOTE: a lot of these functions are the same as HTTPRoute however these target th v1alpha2 API
// this should be refactored once TLSRoute is promoted to v1beta1

func tlsRouteAcceptedCondition(tr *gatewayv1alpha2.TLSRoute, accepted bool, msg string) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               conditionStatusAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonAccepted,
			Message:            msg,
			ObservedGeneration: tr.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               conditionStatusAccepted,
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidTLSRoute",
			Message:            msg,
			ObservedGeneration: tr.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func tlsBackendNotFoundRouteCondition(tr *gatewayv1alpha2.TLSRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonBackendNotFound),
		Message:            msg,
		ObservedGeneration: tr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func tlsNoMatchingListenerPortCondition(tr *gatewayv1alpha2.TLSRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionAccepted),
		Status:             metav1.ConditionFalse,
		Reason:             "NoMatchingParent",
		Message:            msg,
		ObservedGeneration: tr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func tlsNoMatchingListenerHostnameRouteCondition(tr *gatewayv1alpha2.TLSRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionAccepted),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonNoMatchingListenerHostname),
		Message:            msg,
		ObservedGeneration: tr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func tlsRefNotPermittedRouteCondition(tr *gatewayv1alpha2.TLSRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonRefNotPermitted),
		Message:            msg,
		ObservedGeneration: tr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func tlsInvalidKindRouteCondition(tr *gatewayv1alpha2.TLSRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonInvalidKind),
		Message:            msg,
		ObservedGeneration: tr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func RouteReasonNotAllowedByListeners(tr *gatewayv1alpha2.TLSRoute, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1alpha2.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1alpha2.RouteReasonNotAllowedByListeners),
		Message:            msg,
		ObservedGeneration: tr.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func mergeTLSRouteStatusConditions(tr *gatewayv1alpha2.TLSRoute, parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range tr.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		tr.Status.RouteStatus.Parents[index].Conditions = merge(tr.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	tr.Status.RouteStatus.Parents = append(tr.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}
