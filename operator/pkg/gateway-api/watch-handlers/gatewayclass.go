// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// enqueueRequestForOwningGatewayClass returns an event handler that, when given a GatewayClass,
// returns reconcile.Requests for all Gateway objects belonging to the given GatewayClass.
func EnqueueRequestForOwningGatewayClass(c client.Client, logger slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, client.ObjectKeyFromObject(a).String(),
		)
		var reqs []reconcile.Request
		gwList := &gatewayv1.GatewayList{}
		if err := c.List(ctx, gwList); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list Gateways")
			return nil
		}

		for _, gw := range gwList.Items {
			if gw.Spec.GatewayClassName != gatewayv1.ObjectName(a.GetName()) {
				continue
			}
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: gw.Namespace,
					Name:      gw.Name,
				},
			}
			reqs = append(reqs, req)
			scopedLog.InfoContext(ctx,
				"Queueing gateway",
				logfields.K8sNamespace, gw.GetNamespace(),
				logfields.Gateway, gw.GetName(),
			)
		}
		return reqs
	})
}

func EnqueueRequestForCiliumGatewayClassConfig(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(enqueueGatewayClassFromIndex(c, logger, indexers.GatewayClassCiliumGatewayClassConfigsIndex))
}

func enqueueGatewayClassFromIndex(c client.Client, logger *slog.Logger, index string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, client.ObjectKeyFromObject(o),
		)
		list := &gatewayv1.GatewayClassList{}

		if err := c.List(ctx, list, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to list related GatewayClass", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			c := client.ObjectKeyFromObject(&item)
			requests = append(requests, reconcile.Request{NamespacedName: c})
			scopedLog.InfoContext(ctx, "Enqueued GatewayClass for resource", logfields.GatewayClass, c)
		}
		return requests
	}
}
