// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const ExtProcConditionMessagePrefix = "ext_proc: "

// IsExtProcInvalidCondition reports whether a Route condition was set by this
// controller because an ext_proc filter declaration was rejected. It lets
// aggregate-scoped status handling recognise its own conditions without
// disturbing conditions that another aggregate or another feature produced.
//
// The message carries the marker either bare, when the whole Route was
// rejected, or behind the Gateway API rule prefixes used when only some rules
// were dropped.
func IsExtProcInvalidCondition(condition metav1.Condition) bool {
	if condition.Reason != "OrderingConflict" && condition.Reason != string(gatewayv1.RouteReasonIncompatibleFilters) {
		return false
	}

	message := condition.Message
	return strings.HasPrefix(message, ExtProcConditionMessagePrefix) ||
		strings.HasPrefix(message, "Dropped Rule: "+ExtProcConditionMessagePrefix) ||
		strings.HasPrefix(message, "Rejected Rule: "+ExtProcConditionMessagePrefix)
}

func IsParentAttachable(
	reconcileParent metav1.Object,
	route metav1.Object,
	parents []gatewayv1.RouteParentStatus,
	attachedListenerSets []gatewayv1.ListenerSet,
) bool {
	return isParentAttachable(reconcileParent, route, parents, attachedListenerSets, false)
}

// IsParentAttachableIncludingExtProcFailures keeps an ext_proc route in the
// translation model after validation marks its parent rejected. The route must
// remain present so translation can emit a fail-closed response instead of
// allowing a lower-precedence route to handle the request.
func IsParentAttachableIncludingExtProcFailures(
	reconcileParent metav1.Object,
	route metav1.Object,
	parents []gatewayv1.RouteParentStatus,
	attachedListenerSets []gatewayv1.ListenerSet,
) bool {
	return isParentAttachable(reconcileParent, route, parents, attachedListenerSets, true)
}

func isParentAttachable(
	reconcileParent metav1.Object,
	route metav1.Object,
	parents []gatewayv1.RouteParentStatus,
	attachedListenerSets []gatewayv1.ListenerSet,
	includeExtProcFailures bool,
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
			if cond.Type != string(gatewayv1.RouteConditionAccepted) {
				continue
			}
			if cond.Status == metav1.ConditionTrue {
				return true
			}
			if includeExtProcFailures && IsExtProcInvalidCondition(cond) {
				return true
			}
		}
	}
	return false
}
