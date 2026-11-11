// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"github.com/cilium/cilium/pkg/container/set"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	KindHTTPRoute gatewayv1.Kind = "HTTPRoute"
	KindGRPCRoute gatewayv1.Kind = "GRPCRoute"
	KindTLSRoute  gatewayv1.Kind = "TLSRoute"
	KindTCPRoute  gatewayv1.Kind = "TCPRoute"
	KindUDPRoute  gatewayv1.Kind = "UDPRoute"
)

func IsParentAttachable(
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

// GetRouteGroupKind returns the gatewayv1.RouteGroupKind for the given route. It returns a zero
// value for unsupported objects.
func GetRouteGroupKind(route metav1.Object) (kind gatewayv1.RouteGroupKind) {
	switch route.(type) {
	case *gatewayv1.HTTPRoute:
		kind = GatewayRouteGroupKind(KindHTTPRoute)
	case *gatewayv1.GRPCRoute:
		kind = GatewayRouteGroupKind(KindGRPCRoute)
	case *gatewayv1.TLSRoute:
		kind = GatewayRouteGroupKind(KindTLSRoute)
	case *gatewayv1.TCPRoute:
		kind = GatewayRouteGroupKind(KindTCPRoute)
	case *gatewayv1.UDPRoute:
		kind = GatewayRouteGroupKind(KindUDPRoute)
	}
	return
}

func GatewayRouteGroupKind(kind gatewayv1.Kind) gatewayv1.RouteGroupKind {
	return gatewayv1.RouteGroupKind{Kind: kind, Group: new(gatewayv1.Group(gatewayv1.GroupName))}
}

func GatewayRouteGroupKinds(kinds ...gatewayv1.Kind) []gatewayv1.RouteGroupKind {
	res := make([]gatewayv1.RouteGroupKind, 0, len(kinds))
	for _, kind := range kinds {
		res = append(res, GatewayRouteGroupKind(kind))
	}
	return res
}

// supportedRouteKinds returns the kinds supported by the given protocol.
func supportedRouteKinds(protocol gatewayv1.ProtocolType) []gatewayv1.Kind {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []gatewayv1.Kind{KindHTTPRoute, KindGRPCRoute}
	case gatewayv1.TLSProtocolType:
		return []gatewayv1.Kind{KindTLSRoute}
	case gatewayv1.TCPProtocolType:
		return []gatewayv1.Kind{KindTCPRoute}
	case gatewayv1.UDPProtocolType:
		return []gatewayv1.Kind{KindUDPRoute}
	default:
		return nil
	}
}

// GetSupportedRouteKindsForProtocol returns a set of the supported kinds for the given protocol.
func GetSupportedRouteKindsForProtocol(protocol gatewayv1.ProtocolType) set.Set[gatewayv1.Kind] {
	return set.NewSet(supportedRouteKinds(protocol)...)
}

func GetSupportedRouteGroupKindsForProtocol(protocol gatewayv1.ProtocolType) []gatewayv1.RouteGroupKind {
	return GatewayRouteGroupKinds(supportedRouteKinds(protocol)...)
}

// NormalizeAllowedGroupKinds normalizes the given list of allowed Gateway GroupKinds to default
// the group to gatewayv1.GroupName and filter unsupported kinds for the protocol.
func NormalizeAllowedGroupKinds(protocol gatewayv1.ProtocolType, allowed []gatewayv1.RouteGroupKind) []gatewayv1.RouteGroupKind {
	supported := GetSupportedRouteKindsForProtocol(protocol)
	result := make([]gatewayv1.RouteGroupKind, 0, len(allowed))

	for _, allowedGroupKind := range allowed {
		if allowedGroupKind.Group == nil {
			allowedGroupKind.Group = new(gatewayv1.Group(gatewayv1.GroupName))
		}

		if *allowedGroupKind.Group != gatewayv1.GroupName {
			// unsupported group
			continue
		}

		if !supported.Has(allowedGroupKind.Kind) {
			// specified kind is not supported for the listener's protocol so it will be ignored
			continue
		}

		result = append(result, allowedGroupKind)
	}

	return result
}

// IsRouteKindAllowedForListener determines whether the given route should be allowed for the
// listener based on whether it's supported by the listener's protocol and if it's explicitly
// allowed.
func IsRouteKindAllowedForListener(listener gatewayv1.Listener, route metav1.Object) bool {
	routeKind := GetRouteGroupKind(route)
	supported := GetSupportedRouteKindsForProtocol(listener.Protocol)

	if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
		// Per Gateway API spec, when AllowedRoutes.Kinds is unspecified the listener
		// accepts only the route kinds compatible with its protocol.
		return supported.Has(routeKind.Kind)
	}

	// normalize allowed kinds
	for _, kind := range NormalizeAllowedGroupKinds(listener.Protocol, listener.AllowedRoutes.Kinds) {
		if kind.Kind == routeKind.Kind {
			return true
		}
	}

	return false
}

// IsRouteAllowedByListener returns whether route may attach to listener.
func IsRouteAllowedByListener(listenerNamespace string, listener *gatewayv1.Listener, route metav1.Object, namespaceLabels NamespaceLabelIndex) bool {
	return IsRouteKindAllowedForListener(*listener, route) &&
		IsListenerNamespaceAllowed(*listener, route.GetNamespace(), listenerNamespace, namespaceLabels)
}
