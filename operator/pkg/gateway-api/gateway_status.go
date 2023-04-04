// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// setGatewayAccepted inserts or updates the Accepted condition for the provided Gateway resource.
func setGatewayAccepted(gw *gatewayv1beta1.Gateway, accepted bool, msg string) *gatewayv1beta1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusAcceptedCondition(gw, accepted, msg))
	return gw
}

// setGatewayReady inserts or updates the Ready condition for the provided Gateway resource.
func setGatewayReady(gw *gatewayv1beta1.Gateway, ready bool, msg string) *gatewayv1beta1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusReadyCondition(gw, ready, msg))
	return gw
}

func gatewayStatusAcceptedCondition(gw *gatewayv1beta1.Gateway, accepted bool, msg string) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1beta1.GatewayConditionAccepted),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.GatewayConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1beta1.GatewayReasonNoResources),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gatewayStatusReadyCondition(gw *gatewayv1beta1.Gateway, scheduled bool, msg string) metav1.Condition {
	switch scheduled {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.GatewayConditionReady),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1beta1.GatewayReasonReady),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.GatewayConditionReady),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1beta1.GatewayReasonListenersNotReady),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gatewayListenerProgrammedCondition(gw *gatewayv1beta1.Gateway, ready bool, msg string) metav1.Condition {
	switch ready {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.ListenerConditionProgrammed),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
			Reason:             string(gatewayv1beta1.ListenerConditionProgrammed),
			Message:            msg,
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1beta1.ListenerReasonPending),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gatewayListenerInvalidRouteKinds(gw *gatewayv1beta1.Gateway, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1beta1.ListenerConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1beta1.ListenerReasonInvalidRouteKinds),
		Message:            msg,
		ObservedGeneration: gw.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}
