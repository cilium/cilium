// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// setGatewayScheduled inserts or updates the Scheduled condition for the provided Gateway resource.
func setGatewayScheduled(gw *gatewayv1beta1.Gateway, scheduled bool, msg string) *gatewayv1beta1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusScheduledCondition(gw, scheduled, msg))
	return gw
}

// setGatewayReady inserts or updates the Ready condition for the provided Gateway resource.
func setGatewayReady(gw *gatewayv1beta1.Gateway, ready bool, msg string) *gatewayv1beta1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusReadyCondition(gw, ready, msg))
	return gw
}

func gatewayStatusScheduledCondition(gw *gatewayv1beta1.Gateway, scheduled bool, msg string) metav1.Condition {
	switch scheduled {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.GatewayConditionScheduled),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.GatewayConditionScheduled),
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

func gatewayListenerReadyCondition(gw *gatewayv1beta1.Gateway, ready bool, msg string) metav1.Condition {
	switch ready {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.ListenerConditionReady),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
			Reason:             string(gatewayv1beta1.ListenerConditionReady),
			Message:            msg,
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1beta1.ListenerConditionReady),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1beta1.ListenerReasonPending),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}
