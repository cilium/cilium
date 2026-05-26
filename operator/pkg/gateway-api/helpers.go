// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"maps"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	gatewayapihelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	kindHTTPRoute = "HTTPRoute"
	kindTLSRoute  = "TLSRoute"
	kindGRPCRoute = "GRPCRoute"
	kindUDPRoute  = "UDPRoute"
	kindTCPRoute  = "TCPRoute"
)

func GatewayAddressTypePtr(addr gatewayv1.AddressType) *gatewayv1.AddressType {
	return &addr
}

func GroupPtr(name string) *gatewayv1.Group {
	group := gatewayv1.Group(name)
	return &group
}

func KindPtr(name string) *gatewayv1.Kind {
	kind := gatewayv1.Kind(name)
	return &kind
}

func ObjectNamePtr(name string) *gatewayv1.ObjectName {
	objectName := gatewayv1.ObjectName(name)
	return &objectName
}

func groupDerefOr(group *gatewayv1.Group, defaultGroup string) string {
	if group != nil && *group != "" {
		return string(*group)
	}
	return defaultGroup
}

// isAllowed returns true if the provided Route is allowed to attach to given gateway
func isAllowed(gw *gatewayv1.Gateway, route metav1.Object, namespaceLabels gatewayapihelpers.NamespaceLabelIndex) bool {
	for _, listener := range gw.Spec.Listeners {
		if listenerisAllowed(gw, &listener, route, namespaceLabels) {
			return true
		}
	}
	return false
}

// listenerisAllowed reports whether route may attach to listener.
func listenerisAllowed(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, route metav1.Object, namespaceLabels gatewayapihelpers.NamespaceLabelIndex) bool {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
		return gatewayapihelpers.IsListenerNamespaceAllowed(*listener, route.GetNamespace(), gw.GetNamespace(), namespaceLabels)
	}

	// check if route is kind-allowed
	if !isKindAllowed(*listener, route) {
		return false
	}
	return gatewayapihelpers.IsListenerNamespaceAllowed(*listener, route.GetNamespace(), gw.GetNamespace(), namespaceLabels)
}

func isKindAllowed(listener gatewayv1.Listener, route metav1.Object) bool {
	routeKind := getGatewayKindForObject(route)

	if listener.AllowedRoutes.Kinds == nil {
		// Per Gateway API spec, when AllowedRoutes.Kinds is unspecified the listener
		// accepts only the route kinds compatible with its protocol.
		for _, supported := range getSupportedRouteKinds(listener.Protocol) {
			if supported.Kind == routeKind {
				return true
			}
		}
		return false
	}

	for _, kind := range listener.AllowedRoutes.Kinds {
		if (kind.Group == nil || string(*kind.Group) == gatewayv1.GroupName) &&
			kind.Kind == kindHTTPRoute && routeKind == kindHTTPRoute {
			return true
		} else if (kind.Group == nil || string(*kind.Group) == gatewayv1.GroupName) &&
			kind.Kind == kindTLSRoute && routeKind == kindTLSRoute {
			return true
		} else if (kind.Group == nil || string(*kind.Group) == gatewayv1.GroupName) &&
			kind.Kind == kindGRPCRoute && routeKind == kindGRPCRoute {
			return true
		}
	}
	return false
}

func computeHosts[T ~string](gw *gatewayv1.Gateway, hostnames []T, excludeHostNames []T) []string {
	hosts := make([]string, 0, len(hostnames))
	for _, listener := range gw.Spec.Listeners {
		hosts = append(hosts, computeHostsForListener(&listener, hostnames, excludeHostNames)...)
	}

	return hosts
}

func computeHostsForListener[T ~string](listener *gatewayv1.Listener, hostnames []T, excludeHostNames []T) []string {
	return model.ComputeHosts(toStringSlice(hostnames), (*string)(listener.Hostname), toStringSlice(excludeHostNames))
}

func toStringSlice[T ~string](s []T) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}

func getSupportedRouteKinds(protocol gatewayv1.ProtocolType) []gatewayv1.RouteGroupKind {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1.GroupName),
				Kind:  kindHTTPRoute,
			},
			{
				Group: GroupPtr(gatewayv1.GroupName),
				Kind:  kindGRPCRoute,
			},
		}
	case gatewayv1.TLSProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1.GroupName),
				Kind:  kindTLSRoute,
			},
		}
	case gatewayv1.TCPProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1alpha2.GroupName),
				Kind:  kindTCPRoute,
			},
		}
	case gatewayv1.UDPProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1alpha2.GroupName),
				Kind:  kindUDPRoute,
			},
		}
	default:
		return nil
	}
}

func getGatewayKindForObject(obj metav1.Object) gatewayv1.Kind {
	switch obj.(type) {
	case *gatewayv1.HTTPRoute:
		return kindHTTPRoute
	case *gatewayv1.GRPCRoute:
		return kindGRPCRoute
	case *gatewayv1.TLSRoute:
		return kindTLSRoute
	case *gatewayv1alpha2.UDPRoute:
		return kindUDPRoute
	case *gatewayv1alpha2.TCPRoute:
		return kindTCPRoute
	default:
		return "Unknown"
	}
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	} else {
		maps.Copy(left, right)
	}
	return left
}

func setMergedLabelsAndAnnotations(temp, desired client.Object) {
	temp.SetAnnotations(mergeMap(temp.GetAnnotations(), desired.GetAnnotations()))
	temp.SetLabels(mergeMap(temp.GetLabels(), desired.GetLabels()))
}
