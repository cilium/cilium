// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func IsParentAttachable(_ context.Context, reconcileParent metav1.Object, route metav1.Object, parents []gatewayv1.RouteParentStatus) bool {
	for _, rps := range parents {
		if NamespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace()) != reconcileParent.GetNamespace() ||
			string(rps.ParentRef.Name) != reconcileParent.GetName() {
			continue
		}

		acceptedValid := false
		for _, cond := range rps.Conditions {
			if cond.Type == string(gatewayv1.RouteConditionAccepted) && cond.Status == metav1.ConditionTrue {
				acceptedValid = true
			}
		}
		if acceptedValid {
			return true
		}
	}
	return false
}
