// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// NamespaceLabelIndex indexes namespace labels by namespace name.
type NamespaceLabelIndex map[string]map[string]string

func NamespaceDerefOr(namespace *gatewayv1.Namespace, defaultNamespace string) string {
	if namespace != nil && *namespace != "" {
		return string(*namespace)
	}
	return defaultNamespace
}

func NewNamespaceLabelIndex(namespaces []corev1.Namespace) NamespaceLabelIndex {
	index := make(NamespaceLabelIndex, len(namespaces))
	for _, namespace := range namespaces {
		index[namespace.GetName()] = namespace.GetLabels()
	}
	return index
}

// IsListenerNamespaceAllowed checks whether a route in routeNamespace is
// permitted to attach to the given listener based on AllowedRoutes.Namespaces.
func IsListenerNamespaceAllowed(listener gatewayv1.Listener, routeNamespace, gatewayNamespace string, namespaces NamespaceLabelIndex) bool {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
		// Default is Same per Gateway API spec.
		return routeNamespace == gatewayNamespace
	}

	routeNamespaces := listener.AllowedRoutes.Namespaces
	if routeNamespaces.From == nil {
		if routeNamespaces.Selector != nil {
			return isNamespaceSelected(routeNamespaces.Selector, routeNamespace, namespaces)
		}
		// Default is Same per Gateway API spec.
		return routeNamespace == gatewayNamespace
	}

	switch *routeNamespaces.From {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return routeNamespace == gatewayNamespace
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromSelector:
		return isNamespaceSelected(routeNamespaces.Selector, routeNamespace, namespaces)
	default:
		return false
	}
}

func isNamespaceSelected(selector *metav1.LabelSelector, routeNamespace string, namespaces NamespaceLabelIndex) bool {
	labelsForNamespace, ok := namespaces[routeNamespace]
	if !ok {
		return false
	}
	selectorMatcher, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return selectorMatcher.Matches(labels.Set(labelsForNamespace))
}
