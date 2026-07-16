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
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForBackendService returns an event handler that, when passed a
// Service, returns reconcile.Requests for all relevant Gateways where that
// Service is used as a backend for a Route attached to that Gateway.
func EnqueueRequestForBackendService(c client.Client, scheme *runtime.Scheme, logger slog.Logger, controllerName string) handler.EventHandler {
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

		// Then, fetch all GRPCRoutes that reference this service, using the backendServiceIndex
		grpcRouteList := &gatewayv1.GRPCRouteList{}
		if err := c.List(ctx, grpcRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceGRPCRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		tcpRouteEnabled := helpers.HasTCPRouteSupport(scheme)
		tcpRouteList := &gatewayv1.TCPRouteList{}
		if tcpRouteEnabled {
			// Then, fetch all TCPRoutes that reference this service, using the backendServiceIndex
			if err := c.List(ctx, tcpRouteList, &client.ListOptions{
				FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceTCPRouteIndex, client.ObjectKeyFromObject(o).String()),
			}); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to list TCPRoutes", logfields.Error, err)
				return []reconcile.Request{}
			}
		}

		udpRouteEnabled := helpers.HasUDPRouteSupport(scheme)
		udpRouteList := &gatewayv1.UDPRouteList{}
		if udpRouteEnabled {
			// Then, fetch all UDPRoutes that reference this service, using the backendServiceIndex
			if err := c.List(ctx, udpRouteList, &client.ListOptions{
				FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceUDPRouteIndex, client.ObjectKeyFromObject(o).String()),
			}); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to list UDPRoutes", logfields.Error, err)
				return []reconcile.Request{}
			}
		}

		allGatewaysSet, err := getAllGatewaysSetForController(ctx, c, controllerName)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get controller Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// iterate through the HTTPRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, hr := range hrList.Items {
			updateReconcileRequestsForParentRefs(ctx, c, hr.Spec.ParentRefs, hr.Namespace, allGatewaysSet, reconcileRequests)
		}

		// iterate through the TLSRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, tlsr := range tlsrList.Items {
			updateReconcileRequestsForParentRefs(ctx, c, tlsr.Spec.ParentRefs, tlsr.Namespace, allGatewaysSet, reconcileRequests)
		}

		// iterate through the GRPCRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, grpcr := range grpcRouteList.Items {
			updateReconcileRequestsForParentRefs(ctx, c, grpcr.Spec.ParentRefs, grpcr.Namespace, allGatewaysSet, reconcileRequests)
		}

		if tcpRouteEnabled {
			// iterate through the TCPRoutes, update reconcileRequests for each Gateway that is relevant.
			for _, tcpr := range tcpRouteList.Items {
				updateReconcileRequestsForParentRefs(ctx, c, tcpr.Spec.ParentRefs, tcpr.Namespace, allGatewaysSet, reconcileRequests)
			}
		}

		if udpRouteEnabled {
			// iterate through the UDPRoutes, update reconcileRequests for each Gateway that is relevant.
			for _, udpr := range udpRouteList.Items {
				updateReconcileRequestsForParentRefs(ctx, c, udpr.Spec.ParentRefs, udpr.Namespace, allGatewaysSet, reconcileRequests)
			}
		}

		// return the keys of the set, since that's the actual reconcile.Requests.
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}

// EnqueueRequestForBackendServiceImport makes sure that Gateways are reconciled
// if a relevant HTTPRoute backend Service Imports are updated.
func EnqueueRequestForBackendServiceImport(c client.Client, logger slog.Logger, controllerName string) handler.EventHandler {
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

		allGatewaysSet, err := getAllGatewaysSetForController(ctx, c, controllerName)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get controller Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// iterate through the HTTPRoutes, return a reconcile.Request for each Gateway that is relevant.
		for _, hr := range hrList.Items {
			updateReconcileRequestsForParentRefs(ctx, c, hr.Spec.ParentRefs, hr.Namespace, allGatewaysSet, reconcileRequests)
		}

		// return the keys of the set.
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}
