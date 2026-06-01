// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ListenerSetReasonParentNotProgrammed: spec-documented Programmed=False reason
// ([listenerset_types.go] mentions it) for which upstream defines no constant.
const listenerSetReasonParentNotProgrammed gatewayv1.ListenerSetConditionReason = "ParentNotProgrammed"

func setListenerSetAccepted(ls *gatewayv1.ListenerSet, accepted bool, msg string, reason gatewayv1.ListenerSetConditionReason) {
	status := metav1.ConditionFalse

	if accepted {
		status = metav1.ConditionTrue
	}

	ls.Status.Conditions = merge(ls.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func setListenerSetProgrammed(ls *gatewayv1.ListenerSet, status metav1.ConditionStatus, msg string, reason gatewayv1.ListenerSetConditionReason) {
	ls.Status.Conditions = merge(ls.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func setListenerSetEntryStatuses(ls *gatewayv1.ListenerSet, programmed metav1.ConditionStatus, routes []gatewayv1.HTTPRoute) {
	for _, entry := range ls.Spec.Listeners {
		acceptedCondition := metav1.Condition{
			Type:               string(gatewayv1.ListenerEntryConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerEntryReasonAccepted),
			Message:            "Listener Accepted",
			ObservedGeneration: ls.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
		resolvedRefsCondition := metav1.Condition{
			Type:               string(gatewayv1.ListenerEntryConditionResolvedRefs),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerEntryReasonResolvedRefs),
			Message:            "Resolved Refs",
			ObservedGeneration: ls.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}

		programmedReason := gatewayv1.ListenerEntryReasonProgrammed
		programmedMessage := "Listener Programmed"
		if programmed != metav1.ConditionTrue {
			programmedReason = gatewayv1.ListenerEntryReasonPending
			programmedMessage = "Listener not yet programmed"
		}
		programmedCondition := metav1.Condition{
			Type:               string(gatewayv1.ListenerEntryConditionProgrammed),
			Status:             programmed,
			Reason:             string(programmedReason),
			Message:            programmedMessage,
			ObservedGeneration: ls.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}

		supportedKinds := getSupportedRouteKinds(entry.Protocol)
		attachedRoutes := int32(len(filterHTTPRoutesByListenerSetEntry(ls, entry, routes)))

		found := false
		for i := range ls.Status.Listeners {
			if ls.Status.Listeners[i].Name == entry.Name {
				ls.Status.Listeners[i].SupportedKinds = supportedKinds
				ls.Status.Listeners[i].AttachedRoutes = attachedRoutes
				ls.Status.Listeners[i].Conditions = merge(ls.Status.Listeners[i].Conditions,
					acceptedCondition, resolvedRefsCondition, programmedCondition)
				found = true
				break
			}
		}
		if !found {
			ls.Status.Listeners = append(ls.Status.Listeners, gatewayv1.ListenerEntryStatus{
				Name:           entry.Name,
				SupportedKinds: supportedKinds,
				AttachedRoutes: attachedRoutes,
				Conditions:     merge(nil, acceptedCondition, resolvedRefsCondition, programmedCondition),
			})
		}
	}

	// Prune status entries whose listener no longer exists in the spec.
	var pruned []gatewayv1.ListenerEntryStatus
	for _, es := range ls.Status.Listeners {
		for _, entry := range ls.Spec.Listeners {
			if es.Name == entry.Name {
				pruned = append(pruned, es)
				break
			}
		}
	}
	ls.Status.Listeners = pruned
}

func setGatewayAttachedListenerSets(gw *gatewayv1.Gateway, results []listenerSetResult) {
	var n int32
	for _, res := range results {
		if res.accepted {
			n++
		}
	}
	gw.Status.AttachedListenerSets = &n
}

func (r *gatewayReconciler) updateListenerSetStatus(ctx context.Context, original, updated *gatewayv1.ListenerSet) error {
	if cmp.Equal(original.Status, updated.Status, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}

	return r.Client.Status().Update(ctx, updated)
}

func (r *gatewayReconciler) updateListenerSetStatuses(ctx context.Context, results []listenerSetResult, gatewayAccepted bool) error {
	for i := range results {
		res := results[i]
		original := res.ls.DeepCopy()
		updated := res.ls

		switch {
		case !res.accepted:
			// Rejected by the Gateway's allowedListeners gate.
			setListenerSetAccepted(updated, false, res.message, res.reason)
			setListenerSetProgrammed(updated, metav1.ConditionFalse, res.message, res.reason)
			updated.Status.Listeners = nil // Rejected ListenerSet claims no per-entry status.

		case !gatewayAccepted:
			// Allowed to attach, but the parent Gateway itself is not Accepted.
			setListenerSetAccepted(updated, false, "Parent Gateway is not Accepted", gatewayv1.ListenerSetReasonParentNotAccepted)
			setListenerSetProgrammed(updated, metav1.ConditionFalse, "Parent Gateway is not Programmed", listenerSetReasonParentNotProgrammed)
			updated.Status.Listeners = nil

		default:
			// Accepted and programmed (only reached after the CEC is ensured).
			setListenerSetAccepted(updated, true, "ListenerSet Accepted", gatewayv1.ListenerSetReasonAccepted)
			setListenerSetProgrammed(updated, metav1.ConditionTrue, "ListenerSet Programmed", gatewayv1.ListenerSetReasonProgrammed)
			setListenerSetEntryStatuses(updated, metav1.ConditionTrue, res.routes)
		}

		if err := r.updateListenerSetStatus(ctx, original, updated); err != nil {
			return err
		}
	}
	return nil
}
