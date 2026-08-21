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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
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

type listenerConflict struct {
	reason  gatewayv1.ListenerConditionReason
	message string
}

type listenerConflictsBySource map[model.FullyQualifiedResource]map[gatewayv1.SectionName]listenerConflict

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

type ListenerStatusInputs struct {
	MergedListeners        []ingestion.ListenerWithContext
	Namespaces             []corev1.Namespace
	AttachedListenerSets   []gatewayv1.ListenerSet
	DisallowedListenerSets []gatewayv1.ListenerSet
	HTTPRoutes             []gatewayv1.HTTPRoute
	TLSRoutes              []gatewayv1.TLSRoute
	GRPCRoutes             []gatewayv1.GRPCRoute
	TCPRoutes              []gatewayv1.TCPRoute
	UDPRoutes              []gatewayv1.UDPRoute
	ReferenceGrants        []gatewayv1.ReferenceGrant
}

type ListenerStatusResult struct {
	GatewayStatus           ListenersStatus
	MergedAndValidListeners []ingestion.ListenerWithContext
}

type ListenersStatus string

const (
	ListenersStatusNoneValid                    ListenersStatus = "NoneValid"
	ListenersStatusValidWithUnsupportedProtocol ListenersStatus = "SomeValidWithUnsupported"
	ListenersStatusSomeInvalid                  ListenersStatus = "SomeInvalid"
	ListenersStatusAllValid                     ListenersStatus = "AllValid"
)

func NewListenerStatusManager(client client.Client, logger *slog.Logger, cfg ListenerStatusManagerConfig) *ListenerStatusManager {
	return &ListenerStatusManager{
		client:                  client,
		logger:                  logger,
		tcpUDPRouteSupport:      cfg.TCPUDPRouteSupport,
		tcpUDPUnsupportedReason: cfg.TCPUDPUnsupportedReason,
	}
}

func (m *ListenerStatusManager) SetListenerStatuses(ctx context.Context, gw *gatewayv1.Gateway, inputs ListenerStatusInputs) (*ListenerStatusResult, error) {
	namespaceLabels := helpers.NewNamespaceLabelIndex(inputs.Namespaces)

	conflictedListeners := m.conflictsAcrossSources(inputs.MergedListeners)
	conflictFreeListeners := m.filterOutConflictedListeners(inputs.MergedListeners, conflictedListeners)
	mergedAndValidListeners, _ := m.filterOutInvalidListeners(ctx, conflictFreeListeners, inputs.ReferenceGrants)

	gatewayStatus, err := m.setGatewayListenerStatus(
		ctx,
		gw,
		conflictedListeners,
		inputs.HTTPRoutes,
		inputs.TLSRoutes,
		inputs.GRPCRoutes,
		inputs.TCPRoutes,
		inputs.UDPRoutes,
		inputs.ReferenceGrants,
		namespaceLabels,
	)
	if err != nil {
		return nil, err
	}

	if gatewayStatus != ListenersStatusNoneValid {
		if err := m.setListenerSetStatuses(
			ctx,
			gw,
			inputs.AttachedListenerSets,
			conflictedListeners,
			inputs.DisallowedListenerSets,
			inputs.HTTPRoutes,
			inputs.TLSRoutes,
			inputs.GRPCRoutes,
			inputs.TCPRoutes,
			inputs.UDPRoutes,
			inputs.ReferenceGrants,
			namespaceLabels,
		); err != nil {
			return nil, err
		}
	}

	return &ListenerStatusResult{
		GatewayStatus:           gatewayStatus,
		MergedAndValidListeners: mergedAndValidListeners,
	}, nil
}

func (m *ListenerStatusManager) conflictsAcrossSources(listeners []ingestion.ListenerWithContext) listenerConflictsBySource {
	listenersBySource := make(map[model.FullyQualifiedResource][]gatewayv1.Listener)
	var sources []model.FullyQualifiedResource
	for _, listener := range listeners {
		if _, knownSource := listenersBySource[listener.Source]; !knownSource {
			sources = append(sources, listener.Source)
		}
		listenersBySource[listener.Source] = append(listenersBySource[listener.Source], listener.Listener)
	}

	conflicts := make(listenerConflictsBySource)
	accepted := &acceptedListeners{}
	for _, source := range sources {
		var eligible []gatewayv1.Listener

		for _, listener := range listenersBySource[source] {
			if reason := accepted.checkConflict(listener); reason != "" {
				if conflicts[source] == nil {
					conflicts[source] = map[gatewayv1.SectionName]listenerConflict{}
				}
				conflicts[source][listener.Name] = listenerConflict{reason: reason}
				continue
			}

			eligible = append(eligible, listener)
		}

		for name, conflict := range m.conflictsWithinSource(eligible) {
			if conflicts[source] == nil {
				conflicts[source] = map[gatewayv1.SectionName]listenerConflict{}
			}
			conflicts[source][name] = conflict
		}

		for _, listener := range eligible {
			if _, conflicted := conflicts[source][listener.Name]; !conflicted {
				accepted.accept(listener)
			}
		}
	}
	return conflicts
}

func (m *ListenerStatusManager) filterOutConflictedListeners(listeners []ingestion.ListenerWithContext, conflictedListeners listenerConflictsBySource) []ingestion.ListenerWithContext {
	filtered := make([]ingestion.ListenerWithContext, 0, len(listeners))
	for _, listener := range listeners {
		if _, conflicted := conflictedListeners[listener.Source][listener.Name]; conflicted {
			continue
		}
		filtered = append(filtered, listener)
	}
	return filtered
}

func (m *ListenerStatusManager) conflictsWithinSource(listeners []gatewayv1.Listener) map[gatewayv1.SectionName]listenerConflict {
	conflicts := map[gatewayv1.SectionName]listenerConflict{}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			first := &listeners[i]
			second := &listeners[j]
			reason, ok := m.listenerPairConflict(first, second)
			if !ok {
				continue
			}

			conflicts[first.Name] = listenerConflict{
				reason:  reason,
				message: m.listenerConflictMessage(reason, first, second),
			}
			conflicts[second.Name] = listenerConflict{
				reason:  reason,
				message: m.listenerConflictMessage(reason, second, first),
			}
		}
	}

	return conflicts
}

// listenerPairConflict reports whether two listeners that share a Gateway, or a
// Gateway and its ListenerSets, conflict, along with the reason. Listeners on
// different ports never conflict.
func (m *ListenerStatusManager) listenerPairConflict(first, second *gatewayv1.Listener) (gatewayv1.ListenerConditionReason, bool) {
	if first.Port != second.Port {
		return "", false
	}

	firstL4 := m.isL4Protocol(first.Protocol)
	secondL4 := m.isL4Protocol(second.Protocol)

	// L4 listeners own a port outright with no demultiplexing. TCP and UDP on
	// the same port are the only compatible case involving an L4 listener.
	if firstL4 || secondL4 {
		if firstL4 && secondL4 && first.Protocol != second.Protocol {
			return "", false
		}
		return gatewayv1.ListenerReasonProtocolConflict, true
	}

	// HTTPS termination and TLS passthrough both consume the SNI of the same
	// port, so they conflict whenever their hostnames can match the same value.
	if m.isHTTPSAndTLSPassthroughPair(first, second) {
		if helpers.SNIHostnamesIntersect(
			helpers.ListenerHostname(first), helpers.ListenerHostname(second),
		) {
			return gatewayv1.ListenerReasonProtocolConflict, true
		}
		return "", false
	}

	// Listeners of the same muxed protocol demultiplex by hostname, so they only
	// conflict when they claim the exact same hostname.
	if first.Protocol == second.Protocol &&
		m.normalizedListenerHostname(first) == m.normalizedListenerHostname(second) {
		return gatewayv1.ListenerReasonHostnameConflict, true
	}

	return "", false
}

func (m *ListenerStatusManager) isL4Protocol(p gatewayv1.ProtocolType) bool {
	return p == gatewayv1.TCPProtocolType || p == gatewayv1.UDPProtocolType
}

func (m *ListenerStatusManager) isHTTPSAndTLSPassthroughPair(first, second *gatewayv1.Listener) bool {
	return (helpers.IsHTTPSTerminatedListener(first) && helpers.IsTLSPassthroughListener(second)) ||
		(helpers.IsHTTPSTerminatedListener(second) && helpers.IsTLSPassthroughListener(first))
}

func (m *ListenerStatusManager) normalizedListenerHostname(l *gatewayv1.Listener) string {
	if h := helpers.ListenerHostname(l); h != "" {
		return h
	}
	return "*"
}

func (m *ListenerStatusManager) listenerConflictMessage(
	reason gatewayv1.ListenerConditionReason,
	self, other *gatewayv1.Listener,
) string {
	switch {
	case reason == gatewayv1.ListenerReasonHostnameConflict:
		return fmt.Sprintf(
			"Listener conflicts with listener %q: same port %d has overlapping hostnames.",
			other.Name, self.Port,
		)
	case m.isHTTPSAndTLSPassthroughPair(self, other):
		return fmt.Sprintf(
			"Listener conflicts with listener %q: same port %d has overlapping HTTPS and TLS passthrough hostnames.",
			other.Name, self.Port,
		)
	default:
		return fmt.Sprintf(
			"Listener conflicts with listener %q: same port %d has incompatible protocols.",
			other.Name, self.Port,
		)
	}
}

func (m *ListenerStatusManager) setGatewayListenerStatus(
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
			conds = helpers.MergeConditions(conds, listenerConflictedCondition(gw.GetGeneration(), conflict.reason, conflict.message))
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
		conds = helpers.MergeConditions(conds, res.conds...)
		supportedKinds := res.supportedKinds

		if !isValid {
			invalidListeners++
			conds = helpers.MergeConditions(conds,
				listenerAcceptedCondition(gw.GetGeneration(), false, res.invalidReason, "Listener not valid. "+strings.Join(invalidMessages, " ")),
				listenerProgrammedCondition(gw.GetGeneration(), false, gatewayv1.ListenerReasonPending, "Address not ready yet"))
		} else {
			validListeners++
			if !helpers.IsConditionPresent(conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
				conds = helpers.MergeConditions(conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "Resolved Refs",
					ObservedGeneration: gw.GetGeneration(),
					LastTransitionTime: metav1.Now(),
				})
			}
			conds = helpers.MergeConditions(conds,
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

func (m *ListenerStatusManager) setListenerSetStatuses(
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
) error {
	gw.Status.AttachedListenerSets = nil

	for i := range disallowedListenerSets {
		ls := &disallowedListenerSets[i]
		original := ls.DeepCopy()

		setListenerSetAccepted(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
		setListenerSetProgrammed(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)

		if err := m.updateListenerSetStatus(ctx, original, ls); err != nil {
			return fmt.Errorf("failed to update ListenerSet status for %s: %w", client.ObjectKeyFromObject(ls).String(), err)
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
				conds = helpers.MergeConditions(conds,
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
				conds = helpers.MergeConditions(conds, res.conds...)

				if !isValid {
					conds = helpers.MergeConditions(
						conds,
						listenerAcceptedCondition(ls.GetGeneration(), false, res.invalidReason, "Listener not valid. "+strings.Join(res.invalidMessages, " ")),
						listenerProgrammedCondition(ls.GetGeneration(), false, res.invalidReason, "Listener not valid"),
					)
				} else {
					oneValidListener = true

					if !helpers.IsConditionPresent(conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
						conds = helpers.MergeConditions(conds, metav1.Condition{
							Type:               string(gatewayv1.ListenerConditionResolvedRefs),
							Status:             metav1.ConditionTrue,
							Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
							Message:            "Resolved Refs",
							ObservedGeneration: ls.GetGeneration(),
							LastTransitionTime: metav1.Now(),
						})
					}
					conds = helpers.MergeConditions(
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
			return fmt.Errorf("failed to update ListenerSet status for %s: %w", client.ObjectKeyFromObject(ls).String(), err)
		}
	}

	if validAttachedCount > 0 {
		gw.Status.AttachedListenerSets = &validAttachedCount
	}
	return nil
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

	if !m.tcpUDPRouteSupport && m.isL4Protocol(l.Protocol) {
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
			res.conds = helpers.MergeConditions(res.conds, listenerInvalidRouteKinds(params.generation, "Unsupported Route Kinds in allowedRoutes.kinds"))

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
				res.conds = helpers.MergeConditions(res.conds, metav1.Condition{
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
				res.conds = helpers.MergeConditions(res.conds, metav1.Condition{
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
				res.conds = helpers.MergeConditions(res.conds, metav1.Condition{
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

func (m *ListenerStatusManager) filterOutInvalidListeners(ctx context.Context, listeners []ingestion.ListenerWithContext, grants []gatewayv1.ReferenceGrant) ([]ingestion.ListenerWithContext, []ingestion.ListenerWithContext) {
	valid := make([]ingestion.ListenerWithContext, 0, len(listeners))
	invalid := make([]ingestion.ListenerWithContext, 0, len(listeners))
	for _, listener := range listeners {
		res := m.validateListener(ctx, listener.Listener, listenerValidationParams{
			ownerNamespace: listener.Source.Namespace,
			ownerKind:      listener.Source.Kind,
			generation:     listener.SourceGeneration,
			grants:         grants,
			ownerRef: types.NamespacedName{
				Name:      listener.Source.Name,
				Namespace: listener.Source.Namespace,
			}.String(),
		})
		if res.isValid {
			valid = append(valid, listener)
			continue
		}
		invalid = append(invalid, listener)
	}
	return valid, invalid
}

func (m *ListenerStatusManager) parentRefMatched(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, listenerSource *model.FullyQualifiedResource, routeNamespace string, refs []gatewayv1.ParentReference) bool {
	for _, ref := range refs {
		if helpers.IsGateway(ref) {
			if listenerSource != nil && listenerSource.Kind != "Gateway" {
				continue
			}
			if string(ref.Name) == gw.GetName() && gw.GetNamespace() == helpers.NamespaceDerefOr(ref.Namespace, routeNamespace) {
				if ref.SectionName == nil && ref.Port == nil {
					return true
				}
				sectionNameCheck := ref.SectionName == nil || *ref.SectionName == listener.Name
				portCheck := ref.Port == nil || *ref.Port == listener.Port
				if sectionNameCheck && portCheck {
					return true
				}
			}
			continue
		}

		if helpers.IsListenerSet(ref) {
			if listenerSource == nil || listenerSource.Kind != "ListenerSet" {
				continue
			}
			if string(ref.Name) == listenerSource.Name &&
				helpers.NamespaceDerefOr(ref.Namespace, routeNamespace) == listenerSource.Namespace {
				if ref.SectionName == nil && ref.Port == nil {
					return true
				}
				sectionNameCheck := ref.SectionName == nil || *ref.SectionName == listener.Name
				portCheck := ref.Port == nil || *ref.Port == listener.Port
				if sectionNameCheck && portCheck {
					return true
				}
			}
		}
	}
	return false
}

// acceptedListeners is an ordered accumulator of listeners that have already
// won their port. Listeners are checked against it in precedence order, so an
// earlier listener keeps the port and a later conflicting one is rejected.
type acceptedListeners struct {
	listeners []gatewayv1.Listener
}

func (a *acceptedListeners) checkConflict(l gatewayv1.Listener) gatewayv1.ListenerConditionReason {
	manager := &ListenerStatusManager{}
	for i := range a.listeners {
		if reason, ok := manager.listenerPairConflict(&a.listeners[i], &l); ok {
			return reason
		}
	}
	return ""
}

func (a *acceptedListeners) accept(l gatewayv1.Listener) {
	a.listeners = append(a.listeners, l)
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
			m.parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
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
			m.parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
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
			m.parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
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
			m.parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
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
			m.parentRefMatched(gw, listener, listenerSource, route.GetNamespace(), route.Spec.ParentRefs) {
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
