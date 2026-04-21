// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

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
