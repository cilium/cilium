// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func IsParentAttachable(
	_ context.Context,
	reconcileParent metav1.Object,
	route metav1.Object,
	parents []gatewayv1.RouteParentStatus,
	attachedListenerSets []gatewayv1.ListenerSet,
) bool {
	for _, rps := range parents {
		parentNS := NamespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace())
		parentName := string(rps.ParentRef.Name)

		matched := false
		if parentNS == reconcileParent.GetNamespace() && parentName == reconcileParent.GetName() {
			matched = true
		} else if IsListenerSet(rps.ParentRef) {
			for _, ls := range attachedListenerSets {
				if parentNS == ls.GetNamespace() && parentName == ls.GetName() {
					matched = true
					break
				}
			}
		}

		if !matched {
			continue
		}

		// (ajs) Note well that this predicate depends upon looping over a list
		// of conditions that are expected to already be populated. In the
		// future, let's have this type of condition be an explicit mark on an
		// augmented Route type.
		//
		// Also note well, we are first checking the parentRef relationship
		// here, and then checking if the route was accepted. These states
		// should be more than implicitly related, such that this type of
		// function is not needed.
		for _, cond := range rps.Conditions {
			if cond.Type == string(gatewayv1.RouteConditionAccepted) && cond.Status == metav1.ConditionTrue {
				return true
			}
		}
	}
	return false
}
