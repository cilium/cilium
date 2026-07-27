// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForGAMMAHTTPRoute returns an event handler for any changes with HTTP Routes
// belonging to the given Service
func EnqueueRequestForGAMMAHTTPRoute(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}

		return getGammaReconcileRequestsForRoute(ctx, c, a, hr.Spec.CommonRouteSpec, logger, hr.Kind)
	})
}

// EnqueueRequestForGAMMAGRPCRoute returns an event handler for any changes with GRPC Routes
// belonging to the given Service
func EnqueueRequestForGAMMAGRPCRoute(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		grpcr, ok := a.(*gatewayv1.GRPCRoute)
		if !ok {
			return nil
		}

		return getGammaReconcileRequestsForRoute(ctx, c, a, grpcr.Spec.CommonRouteSpec, logger, grpcr.Kind)
	})
}

// getGammaReconcileRequestsForRoute returns a list of GAMMA services to be reconciled based on the supplied route.
func getGammaReconcileRequestsForRoute(ctx context.Context, c client.Client, object metav1.Object, route gatewayv1.CommonRouteSpec, logger *slog.Logger, objKind string) []reconcile.Request {
	var reqs []reconcile.Request

	scopedLog := logger.With(
		logfields.Resource, types.NamespacedName{
			Namespace: object.GetNamespace(),
			Name:      object.GetName(),
		},
	)

	for _, parent := range route.ParentRefs {
		if helpers.IsGateway(parent) {
			continue
		}

		ns := helpers.NamespaceDerefOr(parent.Namespace, object.GetNamespace())

		s := &corev1.Service{}
		if err := c.Get(ctx, types.NamespacedName{
			Namespace: ns,
			Name:      string(parent.Name),
		}, s); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.ErrorContext(ctx, "Failed to get Gamma Service", logfields.Error, err)
			}
			continue
		}

		if !helpers.IsValidGammaService(s) {
			scopedLog.WarnContext(ctx, "Service referenced as GAMMA parent is not valid")
			continue
		}

		scopedLog.InfoContext(ctx, "Enqueued GAMMA Service for Route",
			logfields.K8sNamespace, ns,
			logfields.ParentResource, parent.Name,
			logfields.Kind, objKind,
			logfields.Route, object.GetName())

		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ns,
				Name:      string(parent.Name),
			},
		})
	}

	return reqs
}

func EnqueueRequestForGAMMAReferenceGrant(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(enqueueAllServices(c, logger))
}

func enqueueAllServices(c client.Client, logger *slog.Logger) handler.MapFunc {
	// TODO(youngnick): This approach will scale poorly with large numbers of
	// Services; each ReferenceGrant update will trigger reconciliation of _all_ Services.
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, client.ObjectKeyFromObject(o),
		)
		list := &corev1.ServiceList{}

		if err := c.List(ctx, list, &client.ListOptions{}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to list Service", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			svc := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: svc,
			})
			scopedLog.InfoContext(ctx, "Enqueued Service for resource", logfields.GammaService, svc)
		}
		return requests
	}
}
