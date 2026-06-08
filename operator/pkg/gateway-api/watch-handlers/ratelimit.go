// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForRateLimitPolicy returns an event handler that maps a CiliumRateLimitPolicy
// to its targeted Route's parent Gateways.
func EnqueueRequestForRateLimitPolicy(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		policy, ok := o.(*v2alpha1.CiliumRateLimitPolicy)
		if !ok {
			return nil
		}

		scopedLog := logger.With(
			logfields.Resource, client.ObjectKeyFromObject(policy).String(),
			logfields.LogSubsys, "queue-gw-from-ratelimit-policy",
		)

		target := policy.Spec.TargetRef
		targetKey := types.NamespacedName{
			Namespace: policy.Namespace,
			Name:      string(target.Name),
		}

		// 1. Determine the target Route type and fetch it
		var routeCommon gatewayv1.CommonRouteSpec
		var routeKind string

		switch target.Kind {
		case "HTTPRoute":
			route := &gatewayv1.HTTPRoute{}
			if err := c.Get(ctx, targetKey, route); err != nil {
				if !k8serrors.IsNotFound(err) {
					scopedLog.ErrorContext(ctx, "Failed to get target HTTPRoute", logfields.Error, err)
				}
				return nil
			}
			routeCommon = route.Spec.CommonRouteSpec
			routeKind = "HTTPRoute"
		case "GRPCRoute":
			route := &gatewayv1.GRPCRoute{}
			if err := c.Get(ctx, targetKey, route); err != nil {
				if !k8serrors.IsNotFound(err) {
					scopedLog.ErrorContext(ctx, "Failed to get target GRPCRoute", logfields.Error, err)
				}
				return nil
			}
			routeCommon = route.Spec.CommonRouteSpec
			routeKind = "GRPCRoute"
		default:
			// Unsupported target kind for rate limiting
			return nil
		}

		// 2. Trace back to the parent Gateways using the shared helper
		// This helper (defined in helpers.go) ensures we only reconcile Cilium-managed Gateways
		return getGatewayReconcileRequestsForRoute(ctx, c, o, routeCommon, logger, controllerName)
	})
}
