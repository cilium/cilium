// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	kindGateway   = "Gateway"
	kindHTTPRoute = "HTTPRoute"
	kindTLSRoute  = "TLSRoute"
	kindUDPRoute  = "UDPRoute"
	kindTCPRoute  = "TCPRoute"
	kindService   = "Service"
	kindSecret    = "Secret"
)

func IsGateway(parent gatewayv1beta1.ParentReference) bool {
	return (parent.Kind == nil || *parent.Kind == kindGateway) && (parent.Group == nil || *parent.Group == gatewayv1beta1.GroupName)
}

func IsService(be gatewayv1beta1.BackendObjectReference) bool {
	return (be.Kind == nil || *be.Kind == kindService) && (be.Group == nil || *be.Group == corev1.GroupName)
}

func IsSecret(secret gatewayv1beta1.SecretObjectReference) bool {
	return (secret.Kind == nil || *secret.Kind == kindSecret) && (secret.Group == nil || *secret.Group == corev1.GroupName)
}

func GatewayAddressTypePtr(addr gatewayv1beta1.AddressType) *gatewayv1beta1.AddressType {
	return &addr
}

func GroupPtr(name string) *gatewayv1beta1.Group {
	group := gatewayv1beta1.Group(name)
	return &group
}

func KindPtr(name string) *gatewayv1beta1.Kind {
	kind := gatewayv1beta1.Kind(name)
	return &kind
}

func namespaceDerefOr(namespace *gatewayv1beta1.Namespace, defaultNamespace string) string {
	if namespace != nil && *namespace != "" {
		return string(*namespace)
	}
	return defaultNamespace
}

// isAllowed returns true if the provided HTTPRoute is allowed to attach to given gateway
func isAllowed(ctx context.Context, c client.Client, gw *gatewayv1beta1.Gateway, hr *gatewayv1beta1.HTTPRoute) bool {
	for _, listener := range gw.Spec.Listeners {
		// all routes in the same namespace are allowed for this listener
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			return hr.GetNamespace() == gw.GetNamespace()
		}

		// check if route is kind-allowed
		if !isKindAllowed(listener) {
			continue
		}

		// check if route is namespace-allowed
		switch *listener.AllowedRoutes.Namespaces.From {
		case gatewayv1beta1.NamespacesFromAll:
			return true
		case gatewayv1beta1.NamespacesFromSame:
			if hr.GetNamespace() == gw.GetNamespace() {
				return true
			}
		case gatewayv1beta1.NamespacesFromSelector:
			nsList := &corev1.NamespaceList{}
			selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
			if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
				log.WithError(err).Error("Unable to list namespaces")
				return false
			}

			for _, ns := range nsList.Items {
				if ns.Name == hr.GetNamespace() {
					return true
				}
			}
		}
	}
	return false
}

func isKindAllowed(listener gatewayv1beta1.Listener) bool {
	if listener.AllowedRoutes.Kinds == nil {
		return true
	}

	for _, kind := range listener.AllowedRoutes.Kinds {
		if (kind.Group == nil || string(*kind.Group) == gatewayv1beta1.GroupName) &&
			kind.Kind == kindHTTPRoute {
			return true
		}
	}
	return false
}

func computeHosts(gw *gatewayv1beta1.Gateway, hr *gatewayv1beta1.HTTPRoute) []string {
	hosts := make([]string, 0, len(hr.Spec.Hostnames))
	for _, listener := range gw.Spec.Listeners {
		hosts = append(hosts, model.ComputeHosts(toStringSlice(hr.Spec.Hostnames), (*string)(listener.Hostname))...)
	}

	return hosts
}

func toStringSlice(s []gatewayv1beta1.Hostname) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}

func getSupportedKind(protocol gatewayv1beta1.ProtocolType) gatewayv1beta1.Kind {
	switch protocol {
	case gatewayv1beta1.TLSProtocolType:
		return kindTLSRoute
	case gatewayv1beta1.HTTPSProtocolType:
		return kindHTTPRoute
	case gatewayv1beta1.HTTPProtocolType:
		return kindHTTPRoute
	case gatewayv1beta1.TCPProtocolType:
		return kindTCPRoute
	case gatewayv1beta1.UDPProtocolType:
		return kindUDPRoute
	default:
		return "Unknown"
	}
}
