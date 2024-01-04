// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func CheckGatewayAllowedForNamespace(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	gw, err := input.GetGateway(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}
	hasNamespaceRestriction := false
	for _, listener := range gw.Spec.Listeners {

		if listener.AllowedRoutes == nil {
			continue
		}

		if listener.AllowedRoutes.Namespaces == nil {
			continue
		}
		if parentRef.SectionName != nil && listener.Name != *parentRef.SectionName {
			continue
		}
		// if gateway allows all namespaces, we do not need to check anything here
		if *listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromAll {
			return true, nil
		}

		if *listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
			nsList := &corev1.NamespaceList{}
			selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
			if err := input.GetClient().List(input.GetContext(), nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
				return false, fmt.Errorf("unable to list namespaces: %w", err)
			}

			allowed := false
			for _, ns := range nsList.Items {
				if ns.Name == input.GetNamespace() {
					allowed = true
				}
			}
			if !allowed {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    "Accepted",
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonNotAllowedByListeners),
					Message: input.GetGVK().Kind + " is not allowed to attach to this Gateway due to namespace selector restrictions",
				})

				return false, nil
			}
			return true, nil
		}

		// check if the gateway allows the same namespace as the route
		if *listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSame &&
			input.GetNamespace() == gw.GetNamespace() {
			return true, nil
		}
		hasNamespaceRestriction = true
	}
	if hasNamespaceRestriction {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonNotAllowedByListeners),
			Message: input.GetGVK().Kind + " is not allowed to attach to this Gateway due to namespace restrictions",
		})
		return false, nil
	}
	return true, nil
}

func CheckGatewayRouteKindAllowed(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	gw, err := input.GetGateway(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	for _, listener := range gw.Spec.Listeners {
		if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
			continue
		}

		allowed := false
		routeGVK := input.GetGVK()
		for _, kind := range listener.AllowedRoutes.Kinds {
			if (kind.Group == nil || (kind.Group != nil && *kind.Group == gatewayv1.Group(routeGVK.Group))) &&
				kind.Kind == gatewayv1.Kind(routeGVK.Kind) {
				allowed = true
				break
			}
		}

		if !allowed {
			input.SetParentCondition(parentRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.RouteReasonNotAllowedByListeners),
				Message: routeGVK.Kind + " is not allowed to attach to this Gateway due to route kind restrictions",
			})

			return false, nil
		}
	}

	return true, nil
}

func CheckGatewayMatchingHostnames(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	gw, err := input.GetGateway(parentRef)
	if err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid" + input.GetGVK().Kind,
			Message: err.Error(),
		})

		return false, nil
	}

	if len(computeHosts(gw, input.GetHostnames())) == 0 {

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

func CheckGatewayMatchingPorts(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	gw, err := input.GetGateway(parentRef)
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
		for _, listener := range gw.Spec.Listeners {
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

func CheckGatewayMatchingSection(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	gw, err := input.GetGateway(parentRef)
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
		for _, listener := range gw.Spec.Listeners {
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
