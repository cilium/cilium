// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func pruneRouteParentStatuses(parents []gatewayv1.RouteParentStatus, currentParentRefs []gatewayv1.ParentReference, controllerName string) []gatewayv1.RouteParentStatus {
	filtered := parents[:0]

	for _, parentStatus := range parents {
		if string(parentStatus.ControllerName) != controllerName || slices.ContainsFunc(currentParentRefs, func(ref gatewayv1.ParentReference) bool {
			return reflect.DeepEqual(ref, parentStatus.ParentRef)
		}) {
			filtered = append(filtered, parentStatus)
		}
	}

	return filtered
}

type RouteStatusManager struct {
	client                  client.Client
	logger                  *slog.Logger
	controllerName          string
	includeTCPRoutes        bool
	includeUDPRoutes        bool
	tcpUDPRouteSupport      bool
	tcpUDPUnsupportedReason string
}

type RouteStatusInputs struct {
	HTTPRoutes      []gatewayv1.HTTPRoute
	TLSRoutes       []gatewayv1.TLSRoute
	GRPCRoutes      []gatewayv1.GRPCRoute
	TCPRoutes       []gatewayv1.TCPRoute
	UDPRoutes       []gatewayv1.UDPRoute
	ReferenceGrants []gatewayv1.ReferenceGrant
}

type RouteStatusManagerConfig struct {
	IncludeTCPRoutes        bool
	IncludeUDPRoutes        bool
	TCPUDPRouteSupport      bool
	TCPUDPUnsupportedReason string
}

func NewRouteStatusManager(client client.Client, logger *slog.Logger, controllerName string, cfg RouteStatusManagerConfig) *RouteStatusManager {
	return &RouteStatusManager{
		client:                  client,
		logger:                  logger,
		controllerName:          controllerName,
		includeTCPRoutes:        cfg.IncludeTCPRoutes,
		includeUDPRoutes:        cfg.IncludeUDPRoutes,
		tcpUDPRouteSupport:      cfg.TCPUDPRouteSupport,
		tcpUDPUnsupportedReason: cfg.TCPUDPUnsupportedReason,
	}
}

func (m *RouteStatusManager) SetRouteStatuses(scopedLog *slog.Logger, ctx context.Context, inputs RouteStatusInputs) error {
	if err := m.setHTTPRouteStatuses(scopedLog, ctx, inputs.HTTPRoutes, inputs.ReferenceGrants); err != nil {
		return err
	}
	if err := m.setTLSRouteStatuses(scopedLog, ctx, inputs.TLSRoutes, inputs.ReferenceGrants); err != nil {
		return err
	}
	if m.includeTCPRoutes {
		if err := m.setTCPRouteStatuses(scopedLog, ctx, inputs.TCPRoutes, inputs.ReferenceGrants); err != nil {
			return err
		}
	}
	if m.includeUDPRoutes {
		if err := m.setUDPRouteStatuses(scopedLog, ctx, inputs.UDPRoutes, inputs.ReferenceGrants); err != nil {
			return err
		}
	}
	if err := m.setGRPCRouteStatuses(scopedLog, ctx, inputs.GRPCRoutes, inputs.ReferenceGrants); err != nil {
		return err
	}

	return nil
}

// runCommonRouteChecks runs all the checks that are common across all supported Route types.
//
// Uses the helpers.Input interface to ensure that this still applies as new types are added.
func (m *RouteStatusManager) runCommonRouteChecks(ctx context.Context, input routechecks.Input, parentRefs []gatewayv1.ParentReference, objNamespace string) error {
	for _, parent := range parentRefs {
		if helpers.IsGateway(parent) {
			if err := m.runGatewayRouteChecks(ctx, input, parent, objNamespace); err != nil {
				return err
			}
		} else if helpers.IsListenerSet(parent) {
			if err := m.runListenerSetRouteChecks(ctx, input, parent, objNamespace); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkRouteSupported returns false when route validation should stop for this input.
func (m *RouteStatusManager) checkRouteSupported(input routechecks.Input, parent gatewayv1.ParentReference) bool {
	switch k := input.GetGVK().Kind; k {
	case kindTCPRoute, kindUDPRoute:
		if !m.tcpUDPRouteSupport {
			input.SetParentCondition(parent, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.RouteReasonUnsupportedValue),
				Message: fmt.Sprintf("%s is not supported: %s", k, m.tcpUDPUnsupportedReason),
			})
			input.SetParentCondition(parent, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionUnknown,
				Reason:  string(gatewayv1.RouteReasonPending),
				Message: fmt.Sprintf("Backend references were not evaluated because this route type is not supported: %s", m.tcpUDPUnsupportedReason),
			})
			return false
		}
	}

	return true
}

var gatewayCheckFuncs = []routechecks.CheckWithParentFunc{
	routechecks.CheckGatewayMatchingProtocol,
	routechecks.CheckGatewayRouteKindAllowed,
	routechecks.CheckGatewayMatchingPorts,
	routechecks.CheckGatewayMatchingHostnames,
	routechecks.CheckGatewayMatchingSection,
	routechecks.CheckGatewayAllowedForNamespace,
}

var backendCheckFuncs = []routechecks.CheckWithParentFunc{
	routechecks.CheckAgainstCrossNamespaceBackendReferences,
	routechecks.CheckBackend,
	routechecks.CheckHasServiceImportSupport,
	routechecks.CheckBackendIsExistingService,
}

func runCheckFuncs(
	input routechecks.Input,
	parent gatewayv1.ParentReference,
	fns []routechecks.CheckWithParentFunc,
	errPrefix string,
) error {
	for _, fn := range fns {
		continueCheck, err := fn(input, parent)
		if err != nil {
			return fmt.Errorf("failed to apply %s check: %w", errPrefix, err)
		}
		if !continueCheck {
			break
		}
	}
	return nil
}

func setInitialRouteConditions(input routechecks.Input, parent gatewayv1.ParentReference) {
	input.SetParentCondition(parent, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionAccepted),
		Status:  metav1.ConditionTrue,
		Reason:  string(gatewayv1.RouteReasonAccepted),
		Message: fmt.Sprintf("Accepted %s", input.GetGVK().Kind),
	})
	input.SetParentCondition(parent, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionResolvedRefs),
		Status:  metav1.ConditionTrue,
		Reason:  string(gatewayv1.RouteReasonResolvedRefs),
		Message: "Service reference is valid",
	})
}

func (m *RouteStatusManager) runGatewayRouteChecks(ctx context.Context, input routechecks.Input, parent gatewayv1.ParentReference, objNamespace string) error {
	if !m.parentIsMatchingGateway(ctx, parent, objNamespace) {
		return nil
	}

	if !m.checkRouteSupported(input, parent) {
		return nil
	}

	setInitialRouteConditions(input, parent)

	if err := runCheckFuncs(input, parent, gatewayCheckFuncs, "Gateway"); err != nil {
		return err
	}
	return runCheckFuncs(input, parent, backendCheckFuncs, "Backend")
}

func (m *RouteStatusManager) runListenerSetRouteChecks(ctx context.Context, input routechecks.Input, parent gatewayv1.ParentReference, objNamespace string) error {
	ns := helpers.NamespaceDerefOr(parent.Namespace, objNamespace)
	ls := &gatewayv1.ListenerSet{}
	if err := m.client.Get(ctx, types.NamespacedName{
		Namespace: ns,
		Name:      string(parent.Name),
	}, ls); err != nil {
		return nil
	}

	gwNN := helpers.ListenerSetParentGateway(ls)
	gw := &gatewayv1.Gateway{}
	if err := m.client.Get(ctx, *gwNN, gw); err != nil {
		return nil
	}

	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(ctx, m.client, m.controllerName, m.logger)
	if !hasMatchingControllerFn(gw) {
		return nil
	}

	if !m.checkRouteSupported(input, parent) {
		return nil
	}

	setInitialRouteConditions(input, parent)

	if err := runCheckFuncs(input, parent, gatewayCheckFuncs, "Gateway for ListenerSet"); err != nil {
		return err
	}
	return runCheckFuncs(input, parent, backendCheckFuncs, "Backend for ListenerSet")
}

func (m *RouteStatusManager) parentIsMatchingGateway(ctx context.Context, parent gatewayv1.ParentReference, namespace string) bool {
	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(ctx, m.client, m.controllerName, m.logger)
	if !helpers.IsGateway(parent) {
		return false
	}
	gw := &gatewayv1.Gateway{}
	if err := m.client.Get(ctx, types.NamespacedName{
		Namespace: helpers.NamespaceDerefOr(parent.Namespace, namespace),
		Name:      string(parent.Name),
	}, gw); err != nil {
		return false
	}
	return hasMatchingControllerFn(gw)
}

func (m *RouteStatusManager) setHTTPRouteStatuses(scopedLog *slog.Logger, ctx context.Context, httpRoutes []gatewayv1.HTTPRoute, grants []gatewayv1.ReferenceGrant) error {
	scopedLog.DebugContext(ctx, "Updating HTTPRoute statuses for Gateway", numRoutes, len(httpRoutes))
	for httpRouteIndex, original := range httpRoutes {
		hr := original.DeepCopy()
		hr.Status.Parents = pruneRouteParentStatuses(hr.Status.Parents, hr.Spec.ParentRefs, m.controllerName)

		i := &routechecks.HTTPRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.HTTPRoute, hr),
			Client:         m.client,
			Grants:         grants,
			HTTPRoute:      hr,
			ControllerName: m.controllerName,
		}

		if err := m.runCommonRouteChecks(ctx, i, hr.Spec.ParentRefs, hr.Namespace); err != nil {
			return fmt.Errorf("failure during HTTPRoute checks: %w", err)
		}

		for _, validate := range []func() (metav1.Condition, bool){
			i.ValidateHeaderModifier,
			i.ValidateMatchRegexps,
		} {
			if cond, invalid := validate(); invalid {
				for _, parent := range hr.Status.Parents {
					i.SetParentCondition(parent.ParentRef, cond)
				}
			}
		}

		if err := m.updateHTTPRouteStatus(ctx, scopedLog, &original, hr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}

		httpRoutes[httpRouteIndex].Status = hr.Status
	}

	return nil
}

func (m *RouteStatusManager) setTLSRouteStatuses(scopedLog *slog.Logger, ctx context.Context, tlsRoutes []gatewayv1.TLSRoute, grants []gatewayv1.ReferenceGrant) error {
	scopedLog.Debug("Updating TLSRoute statuses for Gateway", numRoutes, len(tlsRoutes))
	for tlsRouteIndex, original := range tlsRoutes {
		tlsr := original.DeepCopy()
		tlsr.Status.Parents = pruneRouteParentStatuses(tlsr.Status.Parents, tlsr.Spec.ParentRefs, m.controllerName)

		i := &routechecks.TLSRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.TLSRoute, tlsr),
			Client:         m.client,
			Grants:         grants,
			TLSRoute:       tlsr,
			ControllerName: m.controllerName,
		}

		if err := m.runCommonRouteChecks(ctx, i, tlsr.Spec.ParentRefs, tlsr.Namespace); err != nil {
			return fmt.Errorf("failure during TLSRoute checks: %w", err)
		}

		if err := m.updateTLSRouteStatus(ctx, scopedLog, &original, tlsr); err != nil {
			return fmt.Errorf("failed to update TLSRoute status: %w", err)
		}

		tlsRoutes[tlsRouteIndex].Status = tlsr.Status
	}

	return nil
}

func (m *RouteStatusManager) setGRPCRouteStatuses(scopedLog *slog.Logger, ctx context.Context, grpcRoutes []gatewayv1.GRPCRoute, grants []gatewayv1.ReferenceGrant) error {
	scopedLog.Debug("Updating GRPCRoute statuses for Gateway", numRoutes, len(grpcRoutes))
	for grpcRouteIndex, original := range grpcRoutes {
		grpcr := original.DeepCopy()
		grpcr.Status.Parents = pruneRouteParentStatuses(grpcr.Status.Parents, grpcr.Spec.ParentRefs, m.controllerName)

		i := &routechecks.GRPCRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.GRPCRoute, grpcr),
			Client:         m.client,
			Grants:         grants,
			GRPCRoute:      grpcr,
			ControllerName: m.controllerName,
		}

		if err := m.runCommonRouteChecks(ctx, i, grpcr.Spec.ParentRefs, grpcr.Namespace); err != nil {
			return fmt.Errorf("failure during GRPCRoute checks: %w", err)
		}

		for _, validate := range []func() (metav1.Condition, bool){
			i.ValidateHeaderModifier,
			i.ValidateMatchRegexps,
		} {
			if cond, invalid := validate(); invalid {
				for _, parent := range grpcr.Status.Parents {
					i.SetParentCondition(parent.ParentRef, cond)
				}
			}
		}

		if err := m.updateGRPCRouteStatus(ctx, scopedLog, &original, grpcr); err != nil {
			return fmt.Errorf("failed to update GRPCRoute status: %w", err)
		}

		grpcRoutes[grpcRouteIndex].Status = grpcr.Status
	}

	return nil
}

func (m *RouteStatusManager) setTCPRouteStatuses(scopedLog *slog.Logger, ctx context.Context, tcpRoutes []gatewayv1.TCPRoute, grants []gatewayv1.ReferenceGrant) error {
	scopedLog.Debug("Updating TCPRoute statuses for Gateway", numRoutes, len(tcpRoutes))
	for tcpRouteIndex, original := range tcpRoutes {
		tcpr := original.DeepCopy()
		tcpr.Status.Parents = pruneRouteParentStatuses(tcpr.Status.Parents, tcpr.Spec.ParentRefs, m.controllerName)

		i := &routechecks.TCPRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.TCPRoute, tcpr),
			Client:         m.client,
			Grants:         grants,
			TCPRoute:       tcpr,
			ControllerName: m.controllerName,
		}

		if err := m.runCommonRouteChecks(ctx, i, tcpr.Spec.ParentRefs, tcpr.Namespace); err != nil {
			return fmt.Errorf("failure during TCPRoute checks: %w", err)
		}

		if err := m.updateTCPRouteStatus(ctx, scopedLog, &original, tcpr); err != nil {
			return fmt.Errorf("failed to update TCPRoute status: %w", err)
		}

		tcpRoutes[tcpRouteIndex].Status = tcpr.Status
	}

	return nil
}

func (m *RouteStatusManager) setUDPRouteStatuses(scopedLog *slog.Logger, ctx context.Context, udpRoutes []gatewayv1.UDPRoute, grants []gatewayv1.ReferenceGrant) error {
	scopedLog.Debug("Updating UDPRoute statuses for Gateway", numRoutes, len(udpRoutes))
	for udpRouteIndex, original := range udpRoutes {
		udpr := original.DeepCopy()
		udpr.Status.Parents = pruneRouteParentStatuses(udpr.Status.Parents, udpr.Spec.ParentRefs, m.controllerName)

		i := &routechecks.UDPRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.UDPRoute, udpr),
			Client:         m.client,
			Grants:         grants,
			UDPRoute:       udpr,
			ControllerName: m.controllerName,
		}

		if err := m.runCommonRouteChecks(ctx, i, udpr.Spec.ParentRefs, udpr.Namespace); err != nil {
			return fmt.Errorf("failure during UDPRoute checks: %w", err)
		}

		if err := m.updateUDPRouteStatus(ctx, scopedLog, &original, udpr); err != nil {
			return fmt.Errorf("failed to update UDPRoute status: %w", err)
		}

		udpRoutes[udpRouteIndex].Status = udpr.Status
	}

	return nil
}

func (m *RouteStatusManager) updateHTTPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.DebugContext(ctx, "Updating HTTPRoute status", httpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return m.client.Status().Update(ctx, new)
}

func (m *RouteStatusManager) updateTLSRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.TLSRoute, new *gatewayv1.TLSRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating TLSRoute status", tlsRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return m.client.Status().Update(ctx, new)
}

func (m *RouteStatusManager) updateTCPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.TCPRoute, new *gatewayv1.TCPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating TCPRoute status", tcpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return m.client.Status().Update(ctx, new)
}

func (m *RouteStatusManager) updateUDPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.UDPRoute, new *gatewayv1.UDPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating UDPRoute status", udpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return m.client.Status().Update(ctx, new)
}

func (m *RouteStatusManager) updateGRPCRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.GRPCRoute, new *gatewayv1.GRPCRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating GRPCRoute status", grpcRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return m.client.Status().Update(ctx, new)
}
