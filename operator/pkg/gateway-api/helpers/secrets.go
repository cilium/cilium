// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// GatewaySecretIndex indexes Gateways by referenced TLS Secrets.
	GatewaySecretIndex = "gatewaySecretIndex"

	// ListenerSetSecretIndex indexes ListenerSets by referenced TLS Secrets.
	ListenerSetSecretIndex = "listenerSetSecretIndex"
)

func GetGatewaysForSecret(ctx context.Context, c client.Client, obj client.Object, controllerName string, logger *slog.Logger) []*gatewayv1.Gateway {
	scopedLog := logger.With(
		logfields.Resource, obj.GetName(),
	)
	hasMatchingControllerFn := GatewayHasMatchingControllerFn(ctx, c, controllerName, logger)

	secretKey := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}.String()

	gwList := &gatewayv1.GatewayList{}
	if err := c.List(ctx, gwList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(GatewaySecretIndex, secretKey),
	}); err != nil {
		scopedLog.WarnContext(ctx, "Unable to list Gateways", logfields.Error, err)
		return nil
	}

	seen := make(map[types.NamespacedName]struct{})
	var gateways []*gatewayv1.Gateway

	for i := range gwList.Items {
		gw := &gwList.Items[i]
		if !hasMatchingControllerFn(gw) {
			continue
		}
		gwNN := types.NamespacedName{Name: gw.GetName(), Namespace: gw.GetNamespace()}
		if _, ok := seen[gwNN]; ok {
			continue
		}
		seen[gwNN] = struct{}{}
		gateways = append(gateways, gw)
	}

	if HasListenerSetSupport(c.Scheme()) {
		lsList := &gatewayv1.ListenerSetList{}
		if err := c.List(ctx, lsList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(ListenerSetSecretIndex, secretKey),
		}); err != nil {
			scopedLog.WarnContext(ctx, "Unable to list ListenerSets", logfields.Error, err)
			return gateways
		}

		for i := range lsList.Items {
			gwNN := *ListenerSetParentGateway(&lsList.Items[i])
			if _, ok := seen[gwNN]; ok {
				continue
			}
			seen[gwNN] = struct{}{}

			gw := &gatewayv1.Gateway{}
			if err := c.Get(ctx, gwNN, gw); err != nil {
				scopedLog.WarnContext(ctx, "Unable to get Gateway for ListenerSet", logfields.Error, err)
				continue
			}
			if !hasMatchingControllerFn(gw) {
				continue
			}
			gateways = append(gateways, gw)
		}
	}

	return gateways
}
