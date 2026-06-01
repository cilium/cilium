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

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func EnqueueRequestForOwningListenerSet(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		ls, ok := a.(*gatewayv1.ListenerSet)
		if !ok {
			return nil
		}

		scopedLog := logger.With(
			logfields.Resource, types.NamespacedName{Namespace: ls.GetNamespace(), Name: ls.GetName()},
		)

		pr := ls.Spec.ParentRef
		// ParentGatewayReference defaults Group/Kind to Gateway when nil.
		if (pr.Kind != nil && *pr.Kind != "Gateway") || (pr.Group != nil && *pr.Group != gatewayv1.GroupName) {
			return nil
		}

		ns := ls.GetNamespace()
		if pr.Namespace != nil {
			ns = string(*pr.Namespace)
		}

		gw := &gatewayv1.Gateway{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(pr.Name)}, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.ErrorContext(ctx, "Failed to get parent Gateway", logfields.Error, err)
			}

			return nil
		}

		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			scopedLog.DebugContext(ctx, "Parent Gateway does not have matching controller, skipping")

			return nil
		}

		scopedLog.InfoContext(ctx, "Enqueued Gateway for ListenerSet", logfields.Gateway, pr.Name)

		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: string(pr.Name)}}}
	})
}
