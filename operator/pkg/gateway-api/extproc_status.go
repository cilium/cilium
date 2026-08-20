// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	routeReasonOrderingConflict  = gatewayv1.RouteConditionReason("OrderingConflict")
	routeOrderingConflictMessage = "Declared ExtensionRef filter order conflicts with a higher-precedence Route rule; the Route remains accepted and uses the selected aggregate filter order"
)

type extProcOrderingTarget struct {
	route    model.FullyQualifiedResource
	parent   model.FullyQualifiedResource
	listener string
	port     uint32
}

func extProcOrderingTargets(m *model.Model) []extProcOrderingTarget {
	if m == nil {
		return nil
	}
	analysis := model.AnalyzeExtProcOrder(m)
	conflicts := make(map[model.FullyQualifiedResource]struct{}, len(analysis.ConflictedRoutes))
	for _, route := range analysis.ConflictedRoutes {
		conflicts[route] = struct{}{}
	}

	seen := map[extProcOrderingTarget]struct{}{}
	var targets []extProcOrderingTarget
	for _, listener := range m.HTTP {
		if len(listener.Sources) == 0 {
			continue
		}
		parent := listener.Sources[0]
		for _, route := range listener.Routes {
			for _, filter := range route.ExtensionRefFilters {
				source, ok := extProcFilterSource(filter)
				if !ok {
					continue
				}
				if _, ok := conflicts[source]; !ok {
					continue
				}
				target := extProcOrderingTarget{route: source, parent: parent, listener: listener.Name, port: listener.Port}
				if _, ok := seen[target]; ok {
					continue
				}
				seen[target] = struct{}{}
				targets = append(targets, target)
			}
		}
	}
	return targets
}

func extProcFilterSource(filter model.ExtensionRefFilter) (model.FullyQualifiedResource, bool) {
	if filter.SourceRouteRule == nil {
		return model.FullyQualifiedResource{}, false
	}
	return filter.SourceRouteRule.Source, true
}

func groupExtProcOrderingTargets(targets []extProcOrderingTarget) map[model.FullyQualifiedResource][]extProcOrderingTarget {
	grouped := make(map[model.FullyQualifiedResource][]extProcOrderingTarget)
	for _, target := range targets {
		grouped[target.route] = append(grouped[target.route], target)
	}
	return grouped
}

func orderingConflictCondition(generation int64) metav1.Condition {
	return metav1.Condition{
		Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue,
		Reason: string(routeReasonOrderingConflict), Message: routeOrderingConflictMessage,
		ObservedGeneration: generation, LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func acceptedParentCanBeOverlaid(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type == string(gatewayv1.RouteConditionAccepted) {
			return condition.Status == metav1.ConditionTrue
		}
	}
	return false
}

func gatewayParentMatchesExtProcTarget(parent gatewayv1.ParentReference, routeNamespace string, target extProcOrderingTarget) bool {
	if target.parent.Kind == "Gateway" {
		if !helpers.IsGateway(parent) {
			return false
		}
	} else if target.parent.Kind == "ListenerSet" {
		if !helpers.IsListenerSet(parent) {
			return false
		}
	} else {
		return false
	}
	if helpers.NamespaceDerefOr(parent.Namespace, routeNamespace) != target.parent.Namespace || string(parent.Name) != target.parent.Name {
		return false
	}
	if parent.SectionName != nil && string(*parent.SectionName) != target.listener {
		return false
	}
	return parent.Port == nil || uint32(*parent.Port) == target.port
}

func gammaParentMatchesExtProcTarget(parent gatewayv1.ParentReference, routeNamespace string, target extProcOrderingTarget) bool {
	if !helpers.IsGammaService(parent) {
		return false
	}
	if helpers.NamespaceDerefOr(parent.Namespace, routeNamespace) != target.parent.Namespace || string(parent.Name) != target.parent.Name {
		return false
	}
	return parent.Port == nil || uint32(*parent.Port) == target.port
}

func mergeOrderingConflictConditions(conditions []metav1.Condition, generation int64) ([]metav1.Condition, bool) {
	if !acceptedParentCanBeOverlaid(conditions) {
		return conditions, false
	}
	return helpers.MergeConditions(conditions, orderingConflictCondition(generation)), true
}

func routeMatchesOrderingTarget(namespace, name, uid string, target extProcOrderingTarget) bool {
	if namespace != target.route.Namespace || name != target.route.Name {
		return false
	}
	return target.route.UID == "" || uid == "" || target.route.UID == uid
}

func (r *gatewayReconciler) overlayExtProcOrderingConflictsInMemory(m *model.Model, httpRoutes []gatewayv1.HTTPRoute, grpcRoutes []gatewayv1.GRPCRoute) {
	for route, targets := range groupExtProcOrderingTargets(extProcOrderingTargets(m)) {
		switch route.Kind {
		case "HTTPRoute":
			for index := range httpRoutes {
				if !routeMatchesOrderingTarget(httpRoutes[index].Namespace, httpRoutes[index].Name, string(httpRoutes[index].UID), extProcOrderingTarget{route: route}) {
					continue
				}
				for _, target := range targets {
					for parentIndex := range httpRoutes[index].Status.Parents {
						parent := &httpRoutes[index].Status.Parents[parentIndex]
						if gatewayParentMatchesExtProcTarget(parent.ParentRef, httpRoutes[index].Namespace, target) {
							parent.Conditions, _ = mergeOrderingConflictConditions(parent.Conditions, httpRoutes[index].Generation)
						}
					}
				}
			}
		case "GRPCRoute":
			for index := range grpcRoutes {
				if !routeMatchesOrderingTarget(grpcRoutes[index].Namespace, grpcRoutes[index].Name, string(grpcRoutes[index].UID), extProcOrderingTarget{route: route}) {
					continue
				}
				for _, target := range targets {
					for parentIndex := range grpcRoutes[index].Status.Parents {
						parent := &grpcRoutes[index].Status.Parents[parentIndex]
						if gatewayParentMatchesExtProcTarget(parent.ParentRef, grpcRoutes[index].Namespace, target) {
							parent.Conditions, _ = mergeOrderingConflictConditions(parent.Conditions, grpcRoutes[index].Generation)
						}
					}
				}
			}
		}
	}
}

func (r *gammaReconciler) overlayExtProcOrderingConflictsInMemory(m *model.Model, httpRoutes *gatewayv1.HTTPRouteList, grpcRoutes *gatewayv1.GRPCRouteList) {
	for route, targets := range groupExtProcOrderingTargets(extProcOrderingTargets(m)) {
		switch route.Kind {
		case "HTTPRoute":
			for index := range httpRoutes.Items {
				if !routeMatchesOrderingTarget(httpRoutes.Items[index].Namespace, httpRoutes.Items[index].Name, string(httpRoutes.Items[index].UID), extProcOrderingTarget{route: route}) {
					continue
				}
				for _, target := range targets {
					for parentIndex := range httpRoutes.Items[index].Status.Parents {
						parent := &httpRoutes.Items[index].Status.Parents[parentIndex]
						if gammaParentMatchesExtProcTarget(parent.ParentRef, httpRoutes.Items[index].Namespace, target) {
							parent.Conditions, _ = mergeOrderingConflictConditions(parent.Conditions, httpRoutes.Items[index].Generation)
						}
					}
				}
			}
		case "GRPCRoute":
			for index := range grpcRoutes.Items {
				if !routeMatchesOrderingTarget(grpcRoutes.Items[index].Namespace, grpcRoutes.Items[index].Name, string(grpcRoutes.Items[index].UID), extProcOrderingTarget{route: route}) {
					continue
				}
				for _, target := range targets {
					for parentIndex := range grpcRoutes.Items[index].Status.Parents {
						parent := &grpcRoutes.Items[index].Status.Parents[parentIndex]
						if gammaParentMatchesExtProcTarget(parent.ParentRef, grpcRoutes.Items[index].Namespace, target) {
							parent.Conditions, _ = mergeOrderingConflictConditions(parent.Conditions, grpcRoutes.Items[index].Generation)
						}
					}
				}
			}
		}
	}
}

func cloneHTTPRoutes(routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	cloned := make([]gatewayv1.HTTPRoute, len(routes))
	for index := range routes {
		cloned[index] = *routes[index].DeepCopy()
	}
	return cloned
}

func cloneGRPCRoutes(routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	cloned := make([]gatewayv1.GRPCRoute, len(routes))
	for index := range routes {
		cloned[index] = *routes[index].DeepCopy()
	}
	return cloned
}

func (m *RouteStatusManager) persistGatewayRouteStatuses(ctx context.Context, log *slog.Logger, originalHTTPRoutes, desiredHTTPRoutes []gatewayv1.HTTPRoute, originalGRPCRoutes, desiredGRPCRoutes []gatewayv1.GRPCRoute) error {
	for index := range desiredHTTPRoutes {
		if err := m.updateHTTPRouteStatus(ctx, log, &originalHTTPRoutes[index], &desiredHTTPRoutes[index]); err != nil {
			return err
		}
	}
	for index := range desiredGRPCRoutes {
		if err := m.updateGRPCRouteStatus(ctx, log, &originalGRPCRoutes[index], &desiredGRPCRoutes[index]); err != nil {
			return err
		}
	}
	return nil
}

func (r *gammaReconciler) persistRouteStatuses(ctx context.Context, originalHTTPRoutes, desiredHTTPRoutes *gatewayv1.HTTPRouteList, originalGRPCRoutes, desiredGRPCRoutes *gatewayv1.GRPCRouteList) error {
	for index := range desiredHTTPRoutes.Items {
		if err := r.updateHTTPRouteStatus(ctx, &originalHTTPRoutes.Items[index], &desiredHTTPRoutes.Items[index]); err != nil {
			return err
		}
	}
	for index := range desiredGRPCRoutes.Items {
		if err := r.updateGRPCRouteStatus(ctx, &originalGRPCRoutes.Items[index], &desiredGRPCRoutes.Items[index]); err != nil {
			return err
		}
	}
	return nil
}
