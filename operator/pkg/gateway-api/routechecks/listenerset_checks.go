// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func CheckListenerSetAllowedForNamespace(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	ls, err := input.GetListenerSet(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	listeners := helpers.ListenerSetListeners(ls)
	allListenerHostNames := GetAllListenerHostNames(listeners)
	hasNamespaceRestriction := false
	for _, listener := range listeners {
		if parentRef.SectionName != nil && listener.Name != *parentRef.SectionName {
			continue
		}
		if parentRef.Port != nil && listener.Port != *parentRef.Port {
			continue
		}
		if listener.Hostname != nil && len(computeHostsForListener(&listener, input.GetHostnames(), allListenerHostNames)) == 0 {
			continue
		}
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			continue
		}

		hasNamespaceRestriction = true
		switch *listener.AllowedRoutes.Namespaces.From {
		case gatewayv1.NamespacesFromAll:
			return true, nil
		case gatewayv1.NamespacesFromSame:
			if input.GetNamespace() == ls.GetNamespace() {
				return true, nil
			}
		case gatewayv1.NamespacesFromSelector:
			nsList := &corev1.NamespaceList{}
			selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
			if err := input.GetClient().List(input.GetContext(), nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
				return false, fmt.Errorf("unable to list namespaces: %w", err)
			}

			for _, ns := range nsList.Items {
				if ns.Name == input.GetNamespace() {
					return true, nil
				}
			}
		}
	}

	if hasNamespaceRestriction {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonNotAllowedByListeners),
			Message: input.GetGVK().Kind + " is not allowed to attach to this ListenerSet due to namespace restrictions",
		})
	}
	return false, nil
}

func CheckListenerSetRouteKindAllowed(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	ls, err := input.GetListenerSet(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	routeGVK := input.GetGVK()
	hasKindRestriction := false
	for _, listener := range helpers.ListenerSetListeners(ls) {
		if parentRef.SectionName != nil && listener.Name != *parentRef.SectionName {
			continue
		}
		if parentRef.Port != nil && listener.Port != *parentRef.Port {
			continue
		}
		if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
			continue
		}

		hasKindRestriction = true
		for _, kind := range listener.AllowedRoutes.Kinds {
			if (kind.Group == nil || *kind.Group == gatewayv1.Group(routeGVK.Group)) &&
				kind.Kind == gatewayv1.Kind(routeGVK.Kind) {
				return true, nil
			}
		}
	}

	if hasKindRestriction {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonNotAllowedByListeners),
			Message: routeGVK.Kind + " is not allowed to attach to this ListenerSet due to route kind restrictions",
		})

		return false, nil
	}

	return true, nil
}

func CheckListenerSetMatchingHostnames(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	ls, err := input.GetListenerSet(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	if len(computeHosts(helpers.ListenerSetListeners(ls), input.GetHostnames(), nil)) == 0 {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonNoMatchingListenerHostname),
			Message: "No matching listener hostname",
		})

		return false, nil
	}

	return true, nil
}

func CheckListenerSetMatchingPorts(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	ls, err := input.GetListenerSet(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	if parentRef.Port != nil {
		for _, listener := range helpers.ListenerSetListeners(ls) {
			if listener.Port == *parentRef.Port {
				return true, nil
			}
		}
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  "NoMatchingParent",
			Message: fmt.Sprintf("No matching listener with port %d", *parentRef.Port),
		})

		return false, nil
	}

	return true, nil
}

func CheckListenerSetMatchingSection(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	ls, err := input.GetListenerSet(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	if parentRef.SectionName != nil {
		found := false
		for _, listener := range helpers.ListenerSetListeners(ls) {
			if listener.Name == *parentRef.SectionName {
				found = true
				break
			}
		}
		if !found {
			input.SetParentCondition(parentRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  "NoMatchingParent",
				Message: fmt.Sprintf("No matching listener with sectionName %s", *parentRef.SectionName),
			})

			return false, nil
		}
	}

	return true, nil
}

func CheckListenerSetMatchingProtocol(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	ls, err := input.GetListenerSet(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	supportedProtocols := input.GetValidProtocols()

	found := false
	for _, listener := range helpers.ListenerSetListeners(ls) {
		if slices.Contains(supportedProtocols, listener.Protocol) {
			found = true
		}
	}

	if !found {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  "NotAllowedByListeners",
			Message: fmt.Sprintf("No Listener with matching Protocol. Allowed protocols: %s", supportedProtocols),
		})

		return false, nil
	}

	return true, nil
}
