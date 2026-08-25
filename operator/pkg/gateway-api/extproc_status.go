// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

// Route status for rejected ext_proc filter declarations.
//
// operator/pkg/model/extproc_order.go resolves one ext_proc filter order per CEC
// and reports the rules it could not satisfy. This file maps those onto Route
// conditions. Because the order is per aggregate, a rule rejected for one parent
// may be valid for another, so every condition here is scoped to the parent whose
// CEC produced the conflict.

const (
	routeReasonOrderingConflict  = gatewayv1.RouteConditionReason("OrderingConflict")
	routeOrderingConflictMessage = "Declared ExtensionRef filter order conflicts with a higher-precedence Route rule; the Route is rejected for this parent"
)

// extProcOrderingTarget identifies one Route rejected for one parent aggregate.
// A CEC carries a single aggregate ext_proc filter order, so rejection is always
// scoped to the listener that produced the conflict and never leaks to the same
// Route's other parents.
type extProcOrderingTarget struct {
	route    model.FullyQualifiedResource
	parent   model.FullyQualifiedResource
	listener string
	port     uint32
	reason   string
	message  string
}

// extProcOrderingTargets reports Routes whose declared ExtensionRef order cannot
// be satisfied by the aggregate order the parent's CEC must use.
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
				target := extProcOrderingTarget{
					route: source, parent: parent, listener: listener.Name, port: listener.Port,
					reason:  string(routeReasonOrderingConflict),
					message: routeOrderingConflictMessage,
				}
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

// extProcInvalidityTargets reports Routes that ingestion already rejected for a
// static reason, such as a repeated ext_proc reference or an unsupported
// external-callout declaration order.
func extProcInvalidityTargets(m *model.Model) []extProcOrderingTarget {
	if m == nil {
		return nil
	}
	seen := map[extProcOrderingTarget]struct{}{}
	var targets []extProcOrderingTarget
	for _, listener := range m.HTTP {
		if len(listener.Sources) == 0 {
			continue
		}
		for _, route := range listener.Routes {
			if route.ExtProcInvalidReason == "" || route.SourceRoute == nil {
				continue
			}
			target := extProcOrderingTarget{
				route: *route.SourceRoute, parent: listener.Sources[0], listener: listener.Name,
				port: listener.Port, reason: route.ExtProcInvalidReason, message: route.ExtProcInvalidMessage,
			}
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			targets = append(targets, target)
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

// extProcInvalidityKey is the aggregate domain a rejection applies to: one Route
// as seen through one listener of one parent.
type extProcInvalidityKey struct {
	route    model.FullyQualifiedResource
	parent   model.FullyQualifiedResource
	listener string
	port     uint32
}

func groupExtProcInvalidityTargets(targets []extProcOrderingTarget) map[extProcInvalidityKey][]extProcOrderingTarget {
	grouped := make(map[extProcInvalidityKey][]extProcOrderingTarget)
	for _, target := range targets {
		key := extProcInvalidityKey{route: target.route, parent: target.parent, listener: target.listener, port: target.port}
		grouped[key] = append(grouped[key], target)
	}
	return grouped
}

// extProcInvalidityState collapses every rejection recorded for one aggregate
// into a single reason and message. OrderingConflict wins over
// IncompatibleFilters so a mixed cause is reported by its aggregate-level
// reason rather than a static one.
func extProcInvalidityState(targets []extProcOrderingTarget) (reason, message string, ok bool) {
	seen := map[string]struct{}{}
	var parts []string
	for _, target := range targets {
		if target.reason == string(routeReasonOrderingConflict) {
			reason = string(routeReasonOrderingConflict)
		} else if reason == "" {
			reason = string(gatewayv1.RouteReasonIncompatibleFilters)
		}
		if target.message == "" {
			continue
		}
		if _, exists := seen[target.message]; exists {
			continue
		}
		seen[target.message] = struct{}{}
		parts = append(parts, target.message)
	}
	if reason == "" {
		return "", "", false
	}
	sort.Strings(parts)
	return reason, helpers.ExtProcConditionMessagePrefix + strings.Join(parts, "; "), true
}

func mergeExtProcInvalidityConditions(conditions []metav1.Condition, generation int64, reason, message string) []metav1.Condition {
	if !canOverlayExtProcInvalidity(conditions) {
		return conditions
	}
	return helpers.MergeConditions(conditions, metav1.Condition{
		Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionFalse,
		Reason: reason, Message: message, ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

// canOverlayExtProcInvalidity allows this controller to reject an accepted
// parent, or to refresh a rejection it set itself, without overwriting a
// rejection that another check produced for an unrelated reason.
func canOverlayExtProcInvalidity(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type != string(gatewayv1.RouteConditionAccepted) {
			continue
		}
		return condition.Status == metav1.ConditionTrue || helpers.IsExtProcInvalidCondition(condition)
	}
	return false
}

func orderingConflictCondition(generation int64) metav1.Condition {
	return metav1.Condition{
		Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionFalse,
		Reason: string(routeReasonOrderingConflict), Message: helpers.ExtProcConditionMessagePrefix + routeOrderingConflictMessage,
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

// modelRouteMatchesOrderingTarget matches every model route produced by the
// rejected source Route. Rejection is whole-Route: a Route that declares an
// unusable ext_proc order is not partly usable for this parent.
//
// TODO: this also invalidates sibling rules that were themselves valid. The
// Gateway API prefers dropping only the offending rules and reporting the
// remainder with PartiallyInvalid.
func modelRouteMatchesOrderingTarget(route model.HTTPRoute, target extProcOrderingTarget) bool {
	if route.SourceRoute != nil && *route.SourceRoute == target.route {
		return true
	}

	if route.SourceRule != nil && route.SourceRule.Source == target.route {
		return true
	}

	for _, filter := range route.ExtensionRefFilters {
		if filter.SourceRouteRule != nil && filter.SourceRouteRule.Source == target.route {
			return true
		}
	}

	return false
}

// failClosedExtProcOrderingRoutes replaces a rejected Route with a synthetic 500
// inside the affected aggregate. The route must stay in the model rather than be
// dropped, otherwise a lower-precedence Route would silently serve the traffic
// without the processing the user asked for.
func failClosedExtProcOrderingRoutes(m *model.Model, targets []extProcOrderingTarget) {
	for _, target := range targets {
		for listenerIndex := range m.HTTP {
			listener := &m.HTTP[listenerIndex]
			if listener.Name != target.listener || listener.Port != target.port || len(listener.Sources) == 0 || listener.Sources[0] != target.parent {
				continue
			}

			for routeIndex := range listener.Routes {
				route := &listener.Routes[routeIndex]
				if !modelRouteMatchesOrderingTarget(*route, target) {
					continue
				}

				route.DirectResponse = &model.DirectResponse{StatusCode: 500}
				route.Backends = nil
				route.ExternalAuth = nil
				route.ExtensionRefFilters = nil
			}
		}
	}
}

// preserveExtProcOrderingConflictsOutsideGateway keeps rejections this
// controller recorded for parents that the current reconciliation does not own.
// Route status is recomputed from scratch for every parent, so without this a
// reconciliation of Gateway B would clear a conflict that only Gateway A can
// observe, and the next reconciliation of A would set it again.
func (r *gatewayReconciler) preserveExtProcOrderingConflictsOutsideGateway(
	gateway *gatewayv1.Gateway,
	attachedListenerSets []gatewayv1.ListenerSet,
	originalHTTPRoutes, desiredHTTPRoutes []gatewayv1.HTTPRoute,
	originalGRPCRoutes, desiredGRPCRoutes []gatewayv1.GRPCRoute,
) {
	for index := range desiredHTTPRoutes {
		r.preserveExtProcOrderingConflictsOutsideGatewayForRoute(
			gateway,
			attachedListenerSets,
			desiredHTTPRoutes[index].Namespace,
			&originalHTTPRoutes[index].Status.RouteStatus,
			&desiredHTTPRoutes[index].Status.RouteStatus,
		)
	}
	for index := range desiredGRPCRoutes {
		r.preserveExtProcOrderingConflictsOutsideGatewayForRoute(
			gateway,
			attachedListenerSets,
			desiredGRPCRoutes[index].Namespace,
			&originalGRPCRoutes[index].Status.RouteStatus,
			&desiredGRPCRoutes[index].Status.RouteStatus,
		)
	}
}

func (r *gatewayReconciler) preserveExtProcOrderingConflictsOutsideGatewayForRoute(
	gateway *gatewayv1.Gateway,
	attachedListenerSets []gatewayv1.ListenerSet,
	routeNamespace string,
	original, desired *gatewayv1.RouteStatus,
) {
	for _, originalParent := range original.Parents {
		if string(originalParent.ControllerName) != r.controllerName ||
			gatewayAggregateOwnsParent(gateway, attachedListenerSets, routeNamespace, originalParent.ParentRef) {
			continue
		}

		var preserved []metav1.Condition
		for index := range originalParent.Conditions {
			condition := originalParent.Conditions[index]
			if condition.Type == string(gatewayv1.RouteConditionAccepted) &&
				helpers.IsExtProcInvalidCondition(condition) {
				preserved = append(preserved, condition)
			}
		}
		if len(preserved) == 0 {
			continue
		}

		for index := range desired.Parents {
			desiredParent := &desired.Parents[index]
			if desiredParent.ControllerName == originalParent.ControllerName && reflect.DeepEqual(desiredParent.ParentRef, originalParent.ParentRef) {
				desiredParent.Conditions = helpers.MergeConditions(desiredParent.Conditions, preserved...)
				break
			}
		}
	}
}

func gatewayAggregateOwnsParent(gateway *gatewayv1.Gateway, attachedListenerSets []gatewayv1.ListenerSet, routeNamespace string, parent gatewayv1.ParentReference) bool {
	parentNamespace := helpers.NamespaceDerefOr(parent.Namespace, routeNamespace)
	if helpers.IsGateway(parent) {
		return parentNamespace == gateway.Namespace && string(parent.Name) == gateway.Name
	}
	if !helpers.IsListenerSet(parent) {
		return false
	}
	for _, listenerSet := range attachedListenerSets {
		if parentNamespace == listenerSet.Namespace && string(parent.Name) == listenerSet.Name {
			return true
		}
	}
	return false
}

func overlayExtProcInvalidityForGatewayRoutes(httpRoutes []gatewayv1.HTTPRoute, grpcRoutes []gatewayv1.GRPCRoute, targets []extProcOrderingTarget) {
	for key, aggregateTargets := range groupExtProcInvalidityTargets(targets) {
		reason, message, ok := extProcInvalidityState(aggregateTargets)
		if !ok {
			continue
		}
		for index := range httpRoutes {
			if !routeMatchesOrderingTarget(httpRoutes[index].Namespace, httpRoutes[index].Name, string(httpRoutes[index].UID), extProcOrderingTarget{route: key.route}) {
				continue
			}
			for parentIndex := range httpRoutes[index].Status.Parents {
				parent := &httpRoutes[index].Status.Parents[parentIndex]
				if gatewayParentMatchesExtProcTarget(parent.ParentRef, httpRoutes[index].Namespace, aggregateTargets[0]) {
					parent.Conditions = mergeExtProcInvalidityConditions(parent.Conditions, httpRoutes[index].Generation, reason, message)
				}
			}
		}
		for index := range grpcRoutes {
			if !routeMatchesOrderingTarget(grpcRoutes[index].Namespace, grpcRoutes[index].Name, string(grpcRoutes[index].UID), extProcOrderingTarget{route: key.route}) {
				continue
			}
			for parentIndex := range grpcRoutes[index].Status.Parents {
				parent := &grpcRoutes[index].Status.Parents[parentIndex]
				if gatewayParentMatchesExtProcTarget(parent.ParentRef, grpcRoutes[index].Namespace, aggregateTargets[0]) {
					parent.Conditions = mergeExtProcInvalidityConditions(parent.Conditions, grpcRoutes[index].Generation, reason, message)
				}
			}
		}
	}
}

func overlayExtProcInvalidityForGammaRoutes(httpRoutes *gatewayv1.HTTPRouteList, grpcRoutes *gatewayv1.GRPCRouteList, targets []extProcOrderingTarget) {
	for key, aggregateTargets := range groupExtProcInvalidityTargets(targets) {
		reason, message, ok := extProcInvalidityState(aggregateTargets)
		if !ok {
			continue
		}
		for index := range httpRoutes.Items {
			if !routeMatchesOrderingTarget(httpRoutes.Items[index].Namespace, httpRoutes.Items[index].Name, string(httpRoutes.Items[index].UID), extProcOrderingTarget{route: key.route}) {
				continue
			}
			for parentIndex := range httpRoutes.Items[index].Status.Parents {
				parent := &httpRoutes.Items[index].Status.Parents[parentIndex]
				if gammaParentMatchesExtProcTarget(parent.ParentRef, httpRoutes.Items[index].Namespace, aggregateTargets[0]) {
					parent.Conditions = mergeExtProcInvalidityConditions(parent.Conditions, httpRoutes.Items[index].Generation, reason, message)
				}
			}
		}
		for index := range grpcRoutes.Items {
			if !routeMatchesOrderingTarget(grpcRoutes.Items[index].Namespace, grpcRoutes.Items[index].Name, string(grpcRoutes.Items[index].UID), extProcOrderingTarget{route: key.route}) {
				continue
			}
			for parentIndex := range grpcRoutes.Items[index].Status.Parents {
				parent := &grpcRoutes.Items[index].Status.Parents[parentIndex]
				if gammaParentMatchesExtProcTarget(parent.ParentRef, grpcRoutes.Items[index].Namespace, aggregateTargets[0]) {
					parent.Conditions = mergeExtProcInvalidityConditions(parent.Conditions, grpcRoutes.Items[index].Generation, reason, message)
				}
			}
		}
	}
}

// overlayExtProcOrderingConflictsInMemory applies both fail-closed translation
// and route status for every ext_proc rejection this Gateway owns. It runs on
// the computed status view before anything is written, so a Route is never
// persisted as accepted while the model already serves it a 500.
func (r *gatewayReconciler) overlayExtProcOrderingConflictsInMemory(m *model.Model, httpRoutes []gatewayv1.HTTPRoute, grpcRoutes []gatewayv1.GRPCRoute) {
	orderingTargets := extProcOrderingTargets(m)
	targets := append(orderingTargets, extProcInvalidityTargets(m)...)
	failClosedExtProcOrderingRoutes(m, targets)
	for route, targets := range groupExtProcOrderingTargets(orderingTargets) {
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
	overlayExtProcInvalidityForGatewayRoutes(httpRoutes, grpcRoutes, targets)
}

func (r *gammaReconciler) overlayExtProcOrderingConflictsInMemory(m *model.Model, httpRoutes *gatewayv1.HTTPRouteList, grpcRoutes *gatewayv1.GRPCRouteList) {
	orderingTargets := extProcOrderingTargets(m)
	targets := append(orderingTargets, extProcInvalidityTargets(m)...)
	failClosedExtProcOrderingRoutes(m, targets)
	for route, targets := range groupExtProcOrderingTargets(orderingTargets) {
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
	overlayExtProcInvalidityForGammaRoutes(httpRoutes, grpcRoutes, targets)
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
