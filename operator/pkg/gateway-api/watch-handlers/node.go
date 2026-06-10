// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForNodes returns an event handler for any changes to a node's IP address, returns reconcile.Requests
// for all Cilium-relvant Gateways
func EnqueueRequestForNodes(c client.Client, logger *slog.Logger, owningGatewayLabel string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, ns client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.K8sNamespace, ns.GetName(),
		)
		nodeList := &corev1.NodeList{}
		if err := c.List(ctx, nodeList); err != nil {
			scopedLog.WarnContext(ctx, "Unable to list nodes", logfields.Error, err)
			return nil
		}

		gateways, err := getAllCiliumGatewaysSet(ctx, c)

		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		reqs := make([]reconcile.Request, 0, len(gateways))
		svcList := &corev1.ServiceList{}
		svcMap := make(map[string]struct{})

		// for each gateway, filter for the services owned by the gateway
		for gw := range gateways {
			gwSplit := strings.SplitN(gw, "/", 2)
			gwName := gwSplit[1]
			if err := c.List(ctx, svcList, client.MatchingLabels{
				owningGatewayLabel: gwName,
			}); err != nil {
				scopedLog.WarnContext(ctx, "Unable to list services", logfields.Error, err)
			}
			// if the service owned by the gateway is a nodeport, add to map of UID
			for _, svc := range svcList.Items {
				if svc.Spec.Type == "NodePort" {
					svcMap[string(svc.GetOwnerReferences()[0].UID)] = struct{}{}
				}
			}
		}

		// queue up a request for every Cilium related gateway
		for gw := range gateways {
			gwSplit := strings.SplitN(gw, "/", 2)

			if len(gwSplit) != 2 {
				scopedLog.ErrorContext(ctx, "Failed to get namespace name", logfields.Error, err)
				return []reconcile.Request{}
			}

			gwNamespace, gwName := gwSplit[0], gwSplit[1]

			gatewayNamespaceName := types.NamespacedName{
				Namespace: gwNamespace,
				Name:      gwName,
			}

			gateway := &gatewayv1.Gateway{}

			if err := c.Get(ctx, gatewayNamespaceName, gateway); err != nil {
				scopedLog.WarnContext(ctx, "Unable to get gateway", logfields.Error, err)
			}
			if _, err := svcMap[string(gateway.GetUID())]; err {
				// there is no nodeport svc for this gateway, no need to reconcile
				continue
			}
			reqs = append(reqs, reconcile.Request{
				NamespacedName: gatewayNamespaceName,
			})
		}
		return reqs
	})
}
