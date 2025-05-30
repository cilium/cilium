// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CiliumGammaPrefix = "gamma.cilium.io"
)

const (
	CiliumGammaConditionAccepted = CiliumGammaPrefix + "/GammaRoutesAttached"

	CiliumGammaReasonAccepted = "Accepted"
)

const (
	CiliumGammaConditionProgrammed = CiliumGammaPrefix + "/GammaRoutesProgrammed"

	CiliumGammaReasonProgrammed = "Programmed"
)

// setGatewayAccepted inserts or updates the Accepted condition for the provided Gateway resource.
func setGammaServiceAccepted(svc *corev1.Service, accepted bool, msg string, reason string) *corev1.Service {
	svc.Status.Conditions = merge(svc.Status.Conditions, gammaServiceStatusAcceptedCondition(svc, accepted, msg, reason))
	return svc
}

// setGatewayProgrammed inserts or updates the Programmed condition for the provided Gateway resource.
func setGammaServiceProgrammed(svc *corev1.Service, ready bool, msg string, reason string) *corev1.Service {
	svc.Status.Conditions = merge(svc.Status.Conditions, gammaServiceStatusProgrammedCondition(svc, ready, msg, reason))
	return svc
}

func gammaServiceStatusAcceptedCondition(svc *corev1.Service, accepted bool, msg string, reason string) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               CiliumGammaConditionAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: svc.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               CiliumGammaConditionAccepted,
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: svc.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gammaServiceStatusProgrammedCondition(svc *corev1.Service, scheduled bool, msg string, reason string) metav1.Condition {
	switch scheduled {
	case true:
		return metav1.Condition{
			Type:               CiliumGammaConditionProgrammed,
			Status:             metav1.ConditionTrue,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: svc.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               CiliumGammaConditionProgrammed,
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: svc.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}
