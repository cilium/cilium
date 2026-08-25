// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/container/set"
)

const (
	KindHTTPRoute gatewayv1.Kind = "HTTPRoute"
	KindGRPCRoute gatewayv1.Kind = "GRPCRoute"
	KindTLSRoute  gatewayv1.Kind = "TLSRoute"
	KindTCPRoute  gatewayv1.Kind = "TCPRoute"
	KindUDPRoute  gatewayv1.Kind = "UDPRoute"
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
