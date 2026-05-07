// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForBackendTLSPolicy returns an event handler that, when passed a BackendTLSPolicy, returns reconcile.Requests
// for all Cilium-relevant Gateways where that BackendTLSPolicy references a Service that is used as a backend for a
// Route that is attached to that Gateway.
func EnqueueRequestForBackendTLSPolicy(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-backendtlspolicy")

		reconcileRequests := make(map[reconcile.Request]struct{})
		btlsp, ok := o.(*gatewayv1.BackendTLSPolicy)
		if !ok {
			return nil
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet, err := getAllCiliumGatewaysSet(ctx, c)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		ns := o.GetNamespace()
		updateReconcileRequestsForBackendTLSPolicy(ctx, c, scopedLog, allCiliumGatewaysSet, reconcileRequests, btlsp, ns)

		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("BackendTLSPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}

func EnqueueRequestForBackendTLSPolicyConfigMap(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-backendtlspolicy-configmap")

		cfgMap, ok := o.(*corev1.ConfigMap)
		if !ok {
			return []reconcile.Request{}
		}

		cfgMapName := types.NamespacedName{
			Name:      cfgMap.GetName(),
			Namespace: cfgMap.GetNamespace(),
		}

		// Fetch all BackendTLSPolicies that reference this ConfigMap
		btlspList := &gatewayv1.BackendTLSPolicyList{}

		if err := c.List(ctx, btlspList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendTLSPolicyConfigMapIndex, cfgMapName.String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related BackendTLSPolicies for ConfigMap", logfields.Error, err)
			return []reconcile.Request{}
		}
		// If there are no relevant BackendTLSPolicies, then we can skip this ConfigMap.
		if len(btlspList.Items) == 0 {
			return []reconcile.Request{}
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet, err := getAllCiliumGatewaysSet(ctx, c)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		reconcileRequests := make(map[reconcile.Request]struct{})

		for _, btlsp := range btlspList.Items {

			if len(btlsp.Spec.Validation.CACertificateRefs) == 0 {
				// There are no ConfigMaps specified in this BackendTLSPolicy,
				// so this enqueue function doesn't care about it.
				continue
			}

			configMapReferenced := false

			for _, caRef := range btlsp.Spec.Validation.CACertificateRefs {
				if caRef.Group == "" && caRef.Kind == "ConfigMap" && string(caRef.Name) == cfgMap.GetName() {
					configMapReferenced = true
				}
			}

			if !configMapReferenced {
				// Enqueue only cares about ConfigMaps that are referenced by a BackendTLSPolicy
				// If there are no references to this ConfigMap, this BackendTLSPolicy is not relevant.
				continue
			}

			// This BackendTLSPolicy references the ConfigMap being enqueued, check to see if it's in the
			// ownership chain any Cilium-relevant Gateways.
			updateReconcileRequestsForBackendTLSPolicy(ctx, c, scopedLog, allCiliumGatewaysSet, reconcileRequests, &btlsp, cfgMap.GetNamespace())

		}
		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("ConfigMap in BackendTLSPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return recs
	})
}

func updateReconcileRequestsForBackendTLSPolicy(ctx context.Context,
	c client.Client,
	scopedLog *slog.Logger,
	allGatewaysSet map[string]struct{},
	rrSet map[reconcile.Request]struct{},
	btlsp *gatewayv1.BackendTLSPolicy,
	ns string,
) {
	serviceRefs := []string{}
	// First, we collect Service references from the TargetRefs
	for _, target := range btlsp.Spec.TargetRefs {
		if helpers.IsServiceTargetRef(target) {
			serviceRefs = append(serviceRefs, ns+"/"+string(target.Name))
		}
	}
	httpRoutes := []gatewayv1.HTTPRoute{}

	for _, svcName := range serviceRefs {
		// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
		hrList := &gatewayv1.HTTPRouteList{}

		if err := c.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceHTTPRouteIndex, svcName),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return
		}

		httpRoutes = append(httpRoutes, hrList.Items...)
	}
	for _, hr := range httpRoutes {
		updateReconcileRequestsForParentRefs(ctx, c, hr.Spec.ParentRefs, hr.Namespace, allGatewaysSet, rrSet)
	}
}
