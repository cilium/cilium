// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EnqueueRequestForOwningHTTPRoute returns an event handler that, when passed a HTTPRoute, returns reconcile.Requests
// for all Cilium-relevant Gateways associated with that HTTPRoute.
func EnqueueRequestForOwningHTTPRoute(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}

		return getGatewayReconcileRequestsForRoute(context.Background(), c, a, hr.Spec.CommonRouteSpec, logger, controllerName)
	})
}

// EnqueueRequestForOwningTLSRoute returns an event handler that, when passed a TLSRoute, returns reconcile.Requests
// for all Cilium-relevant Gateways associated with that TLSRoute.
func EnqueueRequestForOwningTLSRoute(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.TLSRoute)
		if !ok {
			return nil
		}

		return getGatewayReconcileRequestsForRoute(context.Background(), c, a, hr.Spec.CommonRouteSpec, logger, controllerName)
	})
}

// EnqueueRequestForOwningGRPCRoute returns an event handler that, when passed a GRPCRoute, returns reconcile.Requests
// for any Cilium-relevant Gateways associated with that GRPCRoute.
func EnqueueRequestForOwningGRPCRoute(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		gr, ok := a.(*gatewayv1.GRPCRoute)
		if !ok {
			return nil
		}

		return getGatewayReconcileRequestsForRoute(ctx, c, a, gr.Spec.CommonRouteSpec, logger, controllerName)
	})
}
