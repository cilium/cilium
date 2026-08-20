// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ListenerStatusManager struct {
	client                  client.Client
	logger                  *slog.Logger
	tcpUDPRouteSupport      bool
	tcpUDPUnsupportedReason string
}

type ListenerStatusManagerConfig struct {
	TCPUDPRouteSupport      bool
	TCPUDPUnsupportedReason string
}

type listenerValidationParams struct {
	ownerNamespace string
	ownerKind      string
	generation     int64
	grants         []gatewayv1.ReferenceGrant
	ownerRef       string
}

type listenerValidationResult struct {
	isValid         bool
	supportedKinds  []gatewayv1.RouteGroupKind
	invalidReason   gatewayv1.ListenerConditionReason
	invalidMessages []string
	conds           []metav1.Condition
}

func NewListenerStatusManager(client client.Client, logger *slog.Logger, cfg ListenerStatusManagerConfig) *ListenerStatusManager {
	return &ListenerStatusManager{
		client:                  client,
		logger:                  logger,
		tcpUDPRouteSupport:      cfg.TCPUDPRouteSupport,
		tcpUDPUnsupportedReason: cfg.TCPUDPUnsupportedReason,
	}
}

func (m *ListenerStatusManager) SetGatewayListenerStatus(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	conflictedListeners listenerConflictsBySource,
	httpRoutes []gatewayv1.HTTPRoute,
	tlsRoutes []gatewayv1.TLSRoute,
	grpcRoutes []gatewayv1.GRPCRoute,
	tcpRoutes []gatewayv1.TCPRoute,
	udpRoutes []gatewayv1.UDPRoute,
	grants []gatewayv1.ReferenceGrant,
	namespaceLabels helpers.NamespaceLabelIndex,
) (ListenersStatus, error) {
	conflictedGatewayListeners := conflictedListeners[gatewayFQR(gw)]

	validListeners := 0
	unsupportedProtocolListeners := 0
	invalidListeners := 0
	for _, l := range gw.Spec.Listeners {
		isValid := true
		var invalidMessages []string

		var conds []metav1.Condition

		if conflict, ok := conflictedGatewayListeners[l.Name]; ok {
			conds = merge(conds, listenerConflictedCondition(gw.GetGeneration(), conflict.reason, conflict.message))
			invalidMessages = append(invalidMessages, conflict.message)
			isValid = false
		}

		res := m.validateListener(ctx, l, listenerValidationParams{
			ownerNamespace: gw.Namespace,
			ownerKind:      gw.Kind,
			generation:     gw.GetGeneration(),
			grants:         grants,
			ownerRef:       client.ObjectKeyFromObject(gw).String(),
		})
		if !res.isValid && res.invalidReason == gatewayv1.ListenerReasonUnsupportedProtocol {
			unsupportedProtocolListeners++
		}
		isValid = isValid && res.isValid
		invalidMessages = append(invalidMessages, res.invalidMessages...)
		conds = merge(conds, res.conds...)
		supportedKinds := res.supportedKinds

		if !isValid {
			invalidListeners++
			conds = merge(conds,
				listenerAcceptedCondition(gw.GetGeneration(), false, res.invalidReason, "Listener not valid. "+strings.Join(invalidMessages, " ")),
				listenerProgrammedCondition(gw.GetGeneration(), false, gatewayv1.ListenerReasonPending, "Address not ready yet"))
		} else {
			validListeners++
			if !helpers.IsConditionPresent(conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
				conds = merge(conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "Resolved Refs",
					ObservedGeneration: gw.GetGeneration(),
					LastTransitionTime: metav1.Now(),
				})
			}
			conds = merge(conds,
				listenerAcceptedCondition(gw.GetGeneration(), true, gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
				listenerProgrammedCondition(gw.GetGeneration(), false, gatewayv1.ListenerReasonPending, "Address not ready yet"))
		}
		gwSource := gatewayFQR(gw)
		attachedRoutes := m.countAttachedRoutes(gw, &l, &gwSource, httpRoutes, tlsRoutes, grpcRoutes, tcpRoutes, udpRoutes, namespaceLabels)

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].SupportedKinds = supportedKinds
				gw.Status.Listeners[i].Conditions = conds
				gw.Status.Listeners[i].AttachedRoutes = attachedRoutes
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}
	}

	var newListenersStatus []gatewayv1.ListenerStatus
	for _, ls := range gw.Status.Listeners {
		for _, l := range gw.Spec.Listeners {
			if ls.Name == l.Name {
				newListenersStatus = append(newListenersStatus, ls)
				break
			}
		}
	}
	gw.Status.Listeners = newListenersStatus

	switch {
	case validListeners == 0:
		return ListenersStatusNoneValid, nil
	case unsupportedProtocolListeners > 0:
		return ListenersStatusValidWithUnsupportedProtocol, nil
	case invalidListeners > 0:
		return ListenersStatusSomeInvalid, nil
	default:
		return ListenersStatusAllValid, nil
	}
}

func (m *ListenerStatusManager) SetListenerSetStatuses(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	attachedListenerSets []gatewayv1.ListenerSet,
	conflictedListeners listenerConflictsBySource,
	disallowedListenerSets []gatewayv1.ListenerSet,
	httpRoutes []gatewayv1.HTTPRoute,
	tlsRoutes []gatewayv1.TLSRoute,
	grpcRoutes []gatewayv1.GRPCRoute,
	tcpRoutes []gatewayv1.TCPRoute,
	udpRoutes []gatewayv1.UDPRoute,
	grants []gatewayv1.ReferenceGrant,
	namespaceLabels helpers.NamespaceLabelIndex,
) {
	gw.Status.AttachedListenerSets = nil

	for i := range disallowedListenerSets {
		ls := &disallowedListenerSets[i]
		original := ls.DeepCopy()

		setListenerSetAccepted(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
		setListenerSetProgrammed(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)

		if err := m.updateListenerSetStatus(ctx, original, ls); err != nil {
			m.logger.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err,
				logfields.Resource, client.ObjectKeyFromObject(ls).String())
		}
	}
	var validAttachedCount int32
	for i := range attachedListenerSets {
		ls := &attachedListenerSets[i]
		original := ls.DeepCopy()
		lsSource := listenerSetFQR(ls)

		oneValidListener := false
		var listenerStatuses []gatewayv1.ListenerEntryStatus

		for _, entry := range ls.Spec.Listeners {
			l := helpers.ListenerEntryToListener(entry)
			var conds []metav1.Condition

			conflict, isConflicted := conflictedListeners[lsSource][l.Name]

			if isConflicted {
				conds = merge(conds,
					listenerAcceptedCondition(ls.GetGeneration(), false, conflict.reason, "Listener has a conflict"),
					listenerProgrammedCondition(ls.GetGeneration(), false, conflict.reason, "Listener has a conflict"),
					listenerConflictedCondition(ls.GetGeneration(), conflict.reason, "Listener has a conflict"),
					metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionTrue,
						Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
						Message:            "Resolved Refs",
						ObservedGeneration: ls.GetGeneration(),
						LastTransitionTime: metav1.Now(),
					},
				)
			}

			var supportedKinds []gatewayv1.RouteGroupKind
			if !isConflicted {
				res := m.validateListener(ctx, l, listenerValidationParams{
					ownerNamespace: ls.Namespace,
					ownerKind:      ls.Kind,
					generation:     ls.GetGeneration(),
					grants:         grants,
					ownerRef:       client.ObjectKeyFromObject(ls).String(),
				})
				isValid := res.isValid
				supportedKinds = res.supportedKinds
				conds = merge(conds, res.conds...)

				if !isValid {
					conds = merge(
						conds,
						listenerAcceptedCondition(ls.GetGeneration(), false, res.invalidReason, "Listener not valid. "+strings.Join(res.invalidMessages, " ")),
						listenerProgrammedCondition(ls.GetGeneration(), false, res.invalidReason, "Listener not valid"),
					)
				} else {
					oneValidListener = true

					if !helpers.IsConditionPresent(conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
						conds = merge(conds, metav1.Condition{
							Type:               string(gatewayv1.ListenerConditionResolvedRefs),
							Status:             metav1.ConditionTrue,
							Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
							Message:            "Resolved Refs",
							ObservedGeneration: ls.GetGeneration(),
							LastTransitionTime: metav1.Now(),
						})
					}
					conds = merge(
						conds,
						listenerAcceptedCondition(ls.GetGeneration(), true, gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
						listenerProgrammedCondition(ls.GetGeneration(), true, gatewayv1.ListenerConditionReason(gatewayv1.ListenerConditionProgrammed), "Listener Programmed"),
					)
				}
			}

			attachedRoutes := m.countAttachedRoutes(gw, &l, &lsSource, httpRoutes, tlsRoutes, grpcRoutes, tcpRoutes, udpRoutes, namespaceLabels, *ls)
			listenerStatuses = append(listenerStatuses, gatewayv1.ListenerEntryStatus{
				Name:           entry.Name,
				SupportedKinds: supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}

		ls.Status.Listeners = listenerStatuses

		if oneValidListener {
			validAttachedCount++
			setListenerSetAccepted(ls, true, "ListenerSet is accepted", gatewayv1.ListenerSetReasonAccepted)
			setListenerSetProgrammed(ls, true, "ListenerSet is programmed", gatewayv1.ListenerSetReasonProgrammed)
		} else {
			setListenerSetAccepted(ls, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
			setListenerSetProgrammed(ls, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
		}

		if err := m.updateListenerSetStatus(ctx, original, ls); err != nil {
			m.logger.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err,
				logfields.Resource, client.ObjectKeyFromObject(ls).String())
		}
	}

	if validAttachedCount > 0 {
		gw.Status.AttachedListenerSets = &validAttachedCount
	}
}

func (m *ListenerStatusManager) updateListenerSetStatus(ctx context.Context, original *gatewayv1.ListenerSet, new *gatewayv1.ListenerSet) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return m.client.Status().Update(ctx, new)
}

func (m *ListenerStatusManager) validateListener(ctx context.Context, l gatewayv1.Listener, params listenerValidationParams) listenerValidationResult {
	res := listenerValidationResult{
		isValid:       true,
		invalidReason: gatewayv1.ListenerReasonInvalid,
	}

	allSupported := getSupportedRouteKinds(l.Protocol)
	if allSupported == nil {
		res.invalidMessages = append(res.invalidMessages, "Unsupported Listener Protocol.")
		res.invalidReason = gatewayv1.ListenerReasonUnsupportedProtocol
		res.isValid = false
	}

	if !m.tcpUDPRouteSupport && isL4Protocol(l.Protocol) {
		res.invalidMessages = append(res.invalidMessages,
			fmt.Sprintf("%s listeners are not supported: %s", l.Protocol, m.tcpUDPUnsupportedReason))
		res.invalidReason = gatewayv1.ListenerReasonUnsupportedProtocol
		res.isValid = false
		return res
	}

	if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) > 0 {
		res.supportedKinds = []gatewayv1.RouteGroupKind{}
		for _, supported := range allSupported {
			for _, allowed := range l.AllowedRoutes.Kinds {
				if supported.Kind == allowed.Kind &&
					groupDerefOr(allowed.Group, gatewayv1.GroupName) == string(*supported.Group) {
					res.supportedKinds = append(res.supportedKinds, supported)
					break
				}
			}
		}

		if len(res.supportedKinds) != len(l.AllowedRoutes.Kinds) {
			res.conds = merge(res.conds, listenerInvalidRouteKinds(params.generation, "Unsupported Route Kinds in allowedRoutes.kinds"))

			if len(res.supportedKinds) == 0 {
				res.invalidMessages = append(res.invalidMessages, "None of the Allowed Route Kinds are supported.")
				res.isValid = false
			}
		}
	} else {
		res.supportedKinds = allSupported
	}

	if l.TLS != nil {
		ownerGVK := helpers.GatewayV1GVK(params.ownerKind)
		for _, cert := range l.TLS.CertificateRefs {
			if !helpers.IsSecret(cert) {
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message:            "Invalid CertificateRef",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, must be a Secret.")
				res.isValid = false
				break
			}

			if !helpers.IsSecretReferenceAllowed(params.ownerNamespace, cert, ownerGVK, params.grants) {
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
					Message:            "CertificateRef is not permitted",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, not permitted.")
				res.isValid = false
				break
			}

			if err := m.validateTLSSecret(ctx, helpers.NamespaceDerefOr(cert.Namespace, params.ownerNamespace), string(cert.Name)); err != nil {
				m.logger.InfoContext(ctx, "Found an invalid TLS Secret",
					logfields.Error, err.Error(),
					logfields.Resource, params.ownerRef)
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message:            "Invalid CertificateRef",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, "+err.Error())
				res.isValid = false
				break
			}
		}
		if l.Protocol == gatewayv1.TLSProtocolType && l.TLS.Mode != nil && *l.TLS.Mode == gatewayv1.TLSModeTerminate {
			res.isValid = false
			res.invalidMessages = append(res.invalidMessages, "Using TLSRoute with TLS.mode Terminate is unsupported.")
			res.invalidReason = gatewayv1.ListenerReasonUnsupportedValue
			res.supportedKinds = []gatewayv1.RouteGroupKind{}
		}
	}

	return res
}

func (m *ListenerStatusManager) validateTLSSecret(ctx context.Context, namespace, name string) error {
	secret := &corev1.Secret{}
	if err := m.client.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, secret); err != nil {
		return err
	}

	if !helpers.IsValidPemFormat(secret.Data[corev1.TLSCertKey]) {
		return fmt.Errorf("PEM format error in TLS Certificate")
	}

	if !helpers.IsValidPemFormat(secret.Data[corev1.TLSPrivateKeyKey]) {
		return fmt.Errorf("PEM format error in TLS Key")
	}
	return nil
}

func (m *ListenerStatusManager) countAttachedRoutes(
	gw *gatewayv1.Gateway,
	listener *gatewayv1.Listener,
	listenerSource *model.FullyQualifiedResource,
	httpRoutes []gatewayv1.HTTPRoute,
	tlsRoutes []gatewayv1.TLSRoute,
	grpcRoutes []gatewayv1.GRPCRoute,
	tcpRoutes []gatewayv1.TCPRoute,
	udpRoutes []gatewayv1.UDPRoute,
	namespaceLabels helpers.NamespaceLabelIndex,
	attachedListenerSets ...gatewayv1.ListenerSet,
) int32 {
	var attachedRoutes int32
	attachedRoutes += int32(len(m.filterHTTPRoutesByListener(gw, listener, listenerSource, httpRoutes, namespaceLabels, attachedListenerSets...)))
	attachedRoutes += int32(len(m.filterGRPCRoutesByListener(gw, listener, listenerSource, grpcRoutes, namespaceLabels, attachedListenerSets...)))
	attachedRoutes += int32(len(m.filterTLSRoutesByListener(gw, listener, listenerSource, tlsRoutes, namespaceLabels, attachedListenerSets...)))
	attachedRoutes += int32(len(m.filterTCPRoutesByListener(gw, listener, listenerSource, tcpRoutes, namespaceLabels, attachedListenerSets...)))
	attachedRoutes += int32(len(m.filterUDPRoutesByListener(gw, listener, listenerSource, udpRoutes, namespaceLabels, attachedListenerSets...)))
	return attachedRoutes
}

func (m *ListenerStatusManager) filterHTTPRoutesByListener(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, listenerSource *model.FullyQualifiedResource, routes []gatewayv1.HTTPRoute, namespaceLabels helpers.NamespaceLabelIndex, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.HTTPRoute {
	lsNS := m.listenerOwnerNamespace(gw, listenerSource)
	var filtered []gatewayv1.HTTPRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(lsNS, listener, &route, namespaceLabels) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (m *ListenerStatusManager) filterGRPCRoutesByListener(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, listenerSource *model.FullyQualifiedResource, routes []gatewayv1.GRPCRoute, namespaceLabels helpers.NamespaceLabelIndex, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.GRPCRoute {
	lsNS := m.listenerOwnerNamespace(gw, listenerSource)
	var filtered []gatewayv1.GRPCRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(lsNS, listener, &route, namespaceLabels) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (m *ListenerStatusManager) filterTLSRoutesByListener(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, listenerSource *model.FullyQualifiedResource, routes []gatewayv1.TLSRoute, namespaceLabels helpers.NamespaceLabelIndex, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.TLSRoute {
	lsNS := m.listenerOwnerNamespace(gw, listenerSource)
	var filtered []gatewayv1.TLSRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(lsNS, listener, &route, namespaceLabels) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (m *ListenerStatusManager) filterTCPRoutesByListener(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, listenerSource *model.FullyQualifiedResource, routes []gatewayv1.TCPRoute, namespaceLabels helpers.NamespaceLabelIndex, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.TCPRoute {
	lsNS := m.listenerOwnerNamespace(gw, listenerSource)
	var filtered []gatewayv1.TCPRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(lsNS, listener, &route, namespaceLabels) &&
			parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (m *ListenerStatusManager) filterUDPRoutesByListener(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, listenerSource *model.FullyQualifiedResource, routes []gatewayv1.UDPRoute, namespaceLabels helpers.NamespaceLabelIndex, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.UDPRoute {
	lsNS := m.listenerOwnerNamespace(gw, listenerSource)
	var filtered []gatewayv1.UDPRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(lsNS, listener, &route, namespaceLabels) &&
			parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (m *ListenerStatusManager) listenerOwnerNamespace(gw *gatewayv1.Gateway, listenerSource *model.FullyQualifiedResource) string {
	if listenerSource != nil && listenerSource.Kind == "ListenerSet" {
		return listenerSource.Namespace
	}
	return gw.GetNamespace()
}
