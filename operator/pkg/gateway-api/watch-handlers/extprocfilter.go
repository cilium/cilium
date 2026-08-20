// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForExtProcFilter returns an event handler that, when passed a
// CiliumEnvoyExtProcFilter, returns reconcile.Requests for all Cilium-relevant
// Gateways whose HTTPRoutes/GRPCRoutes reference that filter via an
// ExtensionRef filter.
func EnqueueRequestForExtProcFilter(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		filter, ok := o.(*v2alpha1.CiliumEnvoyExtProcFilter)
		if !ok {
			return nil
		}
		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-ext-proc-filter")
		key := client.ObjectKeyFromObject(filter).String()

		reconcileRequests := make(map[reconcile.Request]struct{})

		hrList := &gatewayv1.HTTPRouteList{}
		if err := c.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.ExtProcFilterHTTPRouteIndex, key),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return nil
		}

		grpcRouteList := &gatewayv1.GRPCRouteList{}
		if err := c.List(ctx, grpcRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.ExtProcFilterGRPCRouteIndex, key),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related GRPCRoutes", logfields.Error, err)
			return nil
		}

		allGatewaysSet, err := getAllGatewaysSetForController(ctx, c, controllerName)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get controller Gateways", logfields.Error, err)
			return nil
		}

		for _, hr := range hrList.Items {
			helpers.UpdateReconcileRequestsForParentRefs(ctx, c, hr.Spec.ParentRefs, hr.Namespace, allGatewaysSet, reconcileRequests)
		}
		for _, gr := range grpcRouteList.Items {
			helpers.UpdateReconcileRequestsForParentRefs(ctx, c, gr.Spec.ParentRefs, gr.Namespace, allGatewaysSet, reconcileRequests)
		}

		return slices.Collect(maps.Keys(reconcileRequests))
	})
}
