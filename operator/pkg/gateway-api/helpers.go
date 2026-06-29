// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"maps"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	gatewayapihelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

// listenerisAllowed reports whether route may attach to listener.
func listenerisAllowed(listenerNamespace string, listener *gatewayv1.Listener, route metav1.Object, namespaceLabels gatewayapihelpers.NamespaceLabelIndex) bool {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
		return gatewayapihelpers.IsListenerNamespaceAllowed(*listener, route.GetNamespace(), listenerNamespace, namespaceLabels)
	}

	// check if route is kind-allowed
	if !isKindAllowed(*listener, route) {
		return false
	}
	return gatewayapihelpers.IsListenerNamespaceAllowed(*listener, route.GetNamespace(), listenerNamespace, namespaceLabels)
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
		} else if (kind.Group == nil || string(*kind.Group) == gatewayv1alpha2.GroupName) &&
			kind.Kind == kindTCPRoute && routeKind == kindTCPRoute {
			return true
		} else if (kind.Group == nil || string(*kind.Group) == gatewayv1alpha2.GroupName) &&
			kind.Kind == kindUDPRoute && routeKind == kindUDPRoute {
			return true
		}
	}
	return false
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

// isListenerSetAllowed determines if a Gateway allows a given ListenerSet
func isListenerSetAllowed(
	ctx context.Context,
	c client.Client,
	gw *gatewayv1.Gateway,
	ls *gatewayv1.ListenerSet,
	logger *slog.Logger,
) bool {
	if gw.Spec.AllowedListeners == nil {
		return false
	}
	ns := gw.Spec.AllowedListeners.Namespaces
	if ns == nil || ns.From == nil {
		return false
	}
	switch *ns.From {
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return ls.GetNamespace() == gw.GetNamespace()
	case gatewayv1.NamespacesFromSelector:
		nsList := &corev1.NamespaceList{}
		selector, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			logger.ErrorContext(ctx, "Unable to parse namespace selector", logfields.Error, err)
			return false
		}
		if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			logger.ErrorContext(ctx, "Unable to list namespaces", logfields.Error, err)
			return false
		}
		for _, n := range nsList.Items {
			if n.Name == ls.GetNamespace() {
				return true
			}
		}
	}
	return false
}

func gatewayFQR(gw *gatewayv1.Gateway) model.FullyQualifiedResource {
	return model.FullyQualifiedResource{
		Name:      gw.GetName(),
		Namespace: gw.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "Gateway",
		UID:       string(gw.GetUID()),
	}
}

func listenerSetFQR(ls *gatewayv1.ListenerSet) model.FullyQualifiedResource {
	return model.FullyQualifiedResource{
		Name:      ls.GetName(),
		Namespace: ls.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "ListenerSet",
		UID:       string(ls.GetUID()),
	}
}

// sortListenerSets sorts ListenerSets by precedence rules
func sortListenerSets(sets []gatewayv1.ListenerSet) {
	sort.Slice(sets, func(i, j int) bool {
		ti := sets[i].CreationTimestamp.Time
		tj := sets[j].CreationTimestamp.Time
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		ni := sets[i].GetNamespace() + "/" + sets[i].GetName()
		nj := sets[j].GetNamespace() + "/" + sets[j].GetName()
		return ni < nj
	})
}

func deduplicateHTTPRoutes(routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.HTTPRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateGRPCRoutes(routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.GRPCRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateTLSRoutes(routes []gatewayv1.TLSRoute) []gatewayv1.TLSRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.TLSRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateTCPRoutes(routes []gatewayv1alpha2.TCPRoute) []gatewayv1alpha2.TCPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1alpha2.TCPRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateUDPRoutes(routes []gatewayv1alpha2.UDPRoute) []gatewayv1alpha2.UDPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1alpha2.UDPRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}
