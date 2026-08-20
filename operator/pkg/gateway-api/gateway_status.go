// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// setGatewayAccepted inserts or updates the Accepted condition for the provided Gateway resource.
func setGatewayAccepted(gw *gatewayv1.Gateway, accepted bool, msg string, reason gatewayv1.GatewayConditionReason) *gatewayv1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusAcceptedCondition(gw, accepted, msg, reason))
	return gw
}

// setGatewayProgrammed inserts or updates the Programmed condition for the provided Gateway resource.
func setGatewayProgrammed(gw *gatewayv1.Gateway, status metav1.ConditionStatus, msg string, reason gatewayv1.GatewayConditionReason) *gatewayv1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusProgrammedCondition(gw, status, msg, reason))
	return gw
}

// setGatewayInsecureFrontendValidationMode adds the warning condition required
// for AllowInsecureFallback and removes it as soon as the mode is no longer in
// use by either the default or a per-port frontend TLS configuration.
func setGatewayInsecureFrontendValidationMode(gw *gatewayv1.Gateway) *gatewayv1.Gateway {
	conditionType := string(gatewayv1.GatewayConditionInsecureFrontendValidationMode)
	if !hasInsecureFrontendValidationMode(gw) {
		meta.RemoveStatusCondition(&gw.Status.Conditions, conditionType)
		return gw
	}

	gw.Status.Conditions = merge(gw.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.GatewayReasonConfigurationChanged),
		Message:            "Gateway is configured to allow insecure frontend certificate validation",
		ObservedGeneration: gw.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	})
	return gw
}

func hasInsecureFrontendValidationMode(gw *gatewayv1.Gateway) bool {
	if gw.Spec.TLS == nil || gw.Spec.TLS.Frontend == nil {
		return false
	}

	frontend := gw.Spec.TLS.Frontend
	if frontend.Default.Validation != nil && frontend.Default.Validation.Mode == gatewayv1.AllowInsecureFallback {
		return true
	}
	for _, perPort := range frontend.PerPort {
		if perPort.TLS.Validation != nil && perPort.TLS.Validation.Mode == gatewayv1.AllowInsecureFallback {
			return true
		}
	}
	return false
}

func gatewayStatusAcceptedCondition(gw *gatewayv1.Gateway, accepted bool, msg string, reason gatewayv1.GatewayConditionReason) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gatewayStatusProgrammedCondition(gw *gatewayv1.Gateway, scheduled metav1.ConditionStatus, msg string, reason gatewayv1.GatewayConditionReason) metav1.Condition {
	switch scheduled {
	case metav1.ConditionTrue:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionTrue,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	case metav1.ConditionUnknown:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionUnknown,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gatewayStatusReadyCondition(gw *gatewayv1.Gateway, scheduled bool, msg string) metav1.Condition {
	switch scheduled {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionReady),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.GatewayReasonReady),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionReady),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.GatewayReasonListenersNotReady),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func listenerProgrammedCondition(generation int64, ready bool, reason gatewayv1.ListenerConditionReason, msg string) metav1.Condition {
	switch ready {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Reason:             string(reason),
			Message:            msg,
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func listenerAcceptedCondition(generation int64, ready bool, reason gatewayv1.ListenerConditionReason, msg string) metav1.Condition {
	switch ready {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Reason:             string(reason),
			Message:            msg,
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func listenerConflictedCondition(generation int64, reason gatewayv1.ListenerConditionReason, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionConflicted),
		Status:             metav1.ConditionTrue,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func listenerInvalidRouteKinds(generation int64, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1.ListenerReasonInvalidRouteKinds),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func setListenerSetAccepted(ls *gatewayv1.ListenerSet, accepted bool, msg string, reason gatewayv1.ListenerSetConditionReason) {
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}
	ls.Status.Conditions = merge(ls.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func setListenerSetProgrammed(ls *gatewayv1.ListenerSet, programmed bool, msg string, reason gatewayv1.ListenerSetConditionReason) {
	status := metav1.ConditionTrue
	if !programmed {
		status = metav1.ConditionFalse
	}
	ls.Status.Conditions = merge(ls.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}
