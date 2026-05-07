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
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForBackendService returns an event handler that, when passed a Service, returns reconcile.Requests
// for all Cilium-relevant Gateways where that Service is used as a backend for a HTTPRoute that is attached to that Gateway.
func EnqueueRequestForBackendService(c client.Client, logger slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		_, ok := o.(*corev1.Service)
		if !ok {
			return nil
		}

		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-backend-svc")

		// Make a set to hold all reconcile requests
		reconcileRequests := make(map[reconcile.Request]struct{})

		// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
		hrList := &gatewayv1.HTTPRouteList{}

		if err := c.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceHTTPRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Then, fetch all TLSRoutes that reference this service, using the backendServiceIndex
		tlsrList := &gatewayv1.TLSRouteList{}

		if err := c.List(ctx, tlsrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceTLSRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.Error("Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		grpcRouteList := &gatewayv1.GRPCRouteList{}
		if err := c.List(ctx, grpcRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceGRPCRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Fetch all the Cilium-relevant Gateways using the indexers.ImplementationGatewayIndex.
		gwList := &gatewayv1.GatewayList{}
		if err := c.List(ctx, gwList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.ImplementationGatewayIndex, "cilium"),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet := make(map[string]struct{})

		for _, gw := range gwList.Items {
			gwFullName := types.NamespacedName{
				Name:      gw.GetName(),
				Namespace: gw.GetNamespace(),
			}
			allCiliumGatewaysSet[gwFullName.String()] = struct{}{}
		}

		// iterate through the HTTPRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, hr := range hrList.Items {
			updateReconcileRequestsForParentRefs(hr.Spec.ParentRefs, hr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		// iterate through the TLSRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, tlsr := range tlsrList.Items {
			updateReconcileRequestsForParentRefs(tlsr.Spec.ParentRefs, tlsr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		// iterate through the TLSRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, grpcr := range grpcRouteList.Items {
			updateReconcileRequestsForParentRefs(grpcr.Spec.ParentRefs, grpcr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		// return the keys of the set, since that's the actual reconcile.Requests.
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}

// EnqueueRequestForBackendServiceImport makes sure that Gateways are reconciled
// if a relevant HTTPRoute backend Service Imports are updated.
func EnqueueRequestForBackendServiceImport(c client.Client, logger slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		_, ok := o.(*mcsapiv1beta1.ServiceImport)
		if !ok {
			return nil
		}

		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-backend-svc-import")

		// make a set to hold all reconcile requests
		reconcileRequests := make(map[reconcile.Request]struct{})

		// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
		hrList := &gatewayv1.HTTPRouteList{}

		if err := c.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceImportHTTPRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Fetch all the Cilium-relevant Gateways using the indexers.ImplementationGatewayIndex.
		gwList := &gatewayv1.GatewayList{}
		if err := c.List(ctx, gwList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.ImplementationGatewayIndex, "cilium"),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet := make(map[string]struct{})
		for _, gw := range gwList.Items {
			gwFullName := types.NamespacedName{
				Name:      gw.GetName(),
				Namespace: gw.GetNamespace(),
			}
			allCiliumGatewaysSet[gwFullName.String()] = struct{}{}
		}

		// iterate through the HTTPRoutes, return a reconcile.Request for each Gateways that is relevant.
		for _, hr := range hrList.Items {
			for _, parent := range hr.Spec.ParentRefs {
				if !helpers.IsGateway(parent) {
					continue
				}
				parentFullName := types.NamespacedName{
					Name:      string(parent.Name),
					Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
				}
				if _, found := allCiliumGatewaysSet[parentFullName.String()]; found {
					reconcileRequests[reconcile.Request{NamespacedName: parentFullName}] = struct{}{}
				}
			}
		}

		// return the keys of the set.
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}
