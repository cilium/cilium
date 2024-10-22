// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func CheckGammaServiceAllowedForNamespace(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	svc, err := input.GetParentGammaService(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})
		return false, nil
	}

	if input.GetNamespace() != svc.GetNamespace() {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonNoMatchingParent),
			Message: input.GetGVK().Kind + " is not allowed to attach to this Service - it and the Service must be in the same namespace",
		})
		return false, nil
	}
	return true, nil
}
