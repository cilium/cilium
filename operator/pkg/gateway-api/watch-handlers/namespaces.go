// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForAllowedNamespace returns an event handler for any changes
// with allowed namespaces
func EnqueueRequestForAllowedNamespace(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, ns client.Object) []reconcile.Request {
		gateways := getGatewaysForNamespace(ctx, c, ns, logger)
		reqs := make([]reconcile.Request, 0, len(gateways))
		for _, gw := range gateways {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: gw,
			})
		}
		return reqs
	})
}

func getGatewaysForNamespace(ctx context.Context, c client.Client, ns client.Object, logger *slog.Logger) []types.NamespacedName {
	scopedLog := logger.With(
		logfields.K8sNamespace, ns.GetName(),
	)

	gwList := &gatewayv1.GatewayList{}
	if err := c.List(ctx, gwList); err != nil {
		scopedLog.WarnContext(ctx, "Unable to list Gateways", logfields.Error, err)
		return nil
	}

	var gateways []types.NamespacedName
	for _, gw := range gwList.Items {
		for _, l := range gw.Spec.Listeners {
			if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil {
				continue
			}

			switch *l.AllowedRoutes.Namespaces.From {
			case gatewayv1.NamespacesFromAll:
				gateways = append(gateways, client.ObjectKey{
					Namespace: gw.GetNamespace(),
					Name:      gw.GetName(),
				})
			case gatewayv1.NamespacesFromSame:
				if ns.GetName() == gw.GetNamespace() {
					gateways = append(gateways, client.ObjectKey{
						Namespace: gw.GetNamespace(),
						Name:      gw.GetName(),
					})
				}
			case gatewayv1.NamespacesFromSelector:
				if l.AllowedRoutes.Namespaces.Selector == nil {
					scopedLog.WarnContext(ctx, "AllowedRoutes namespace set to Selector but no selector specified", logfields.Gateway, gw.GetName())
					continue
				}
				nsList := &corev1.NamespaceList{}
				err := c.List(ctx, nsList, client.MatchingLabels(l.AllowedRoutes.Namespaces.Selector.MatchLabels))
				if err != nil {
					scopedLog.WarnContext(ctx, "Unable to list Namespaces", logfields.Error, err)
					return nil
				}
				for _, item := range nsList.Items {
					if item.GetName() == ns.GetName() {
						gateways = append(gateways, client.ObjectKey{
							Namespace: gw.GetNamespace(),
							Name:      gw.GetName(),
						})
					}
				}
			}
		}
	}
	return gateways
}
