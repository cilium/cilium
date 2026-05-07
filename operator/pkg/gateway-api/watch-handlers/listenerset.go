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

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func EnqueueRequestForListenerSetOwner(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		ls, ok := a.(*gatewayv1.ListenerSet)
		if !ok {
			return nil
		}

		scopedLog := logger.With(
			logfields.Resource, types.NamespacedName{
				Namespace: ls.GetNamespace(),
				Name:      ls.GetName(),
			},
		)

		gwNN := helpers.ListenerSetParentGateway(ls)

		gw := &gatewayv1.Gateway{}
		if err := c.Get(ctx, *gwNN, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.ErrorContext(ctx, "Failed to get Gateway for ListenerSet", logfields.Error, err)
			}
			return nil
		}

		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			scopedLog.DebugContext(ctx, "Gateway does not have matching controller, skipping")
			return nil
		}

		scopedLog.InfoContext(ctx,
			"Enqueued gateway for ListenerSet",
			logfields.K8sNamespace, gwNN.Namespace,
			logfields.Gateway, gwNN.Name,
		)

		return []reconcile.Request{
			{
				NamespacedName: *gwNN,
			},
		}
	})
}
