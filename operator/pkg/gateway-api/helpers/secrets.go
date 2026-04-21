// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func GetGatewaysForSecret(ctx context.Context, c client.Client, obj client.Object, logger *slog.Logger) []*gatewayv1.Gateway {
	scopedLog := logger.With(
		logfields.Resource, obj.GetName(),
	)

	gwList := &gatewayv1.GatewayList{}
	if err := c.List(ctx, gwList); err != nil {
		scopedLog.WarnContext(ctx, "Unable to list Gateways", logfields.Error, err)
		return nil
	}

	var gateways []*gatewayv1.Gateway
	for _, gw := range gwList.Items {
		for _, l := range gw.Spec.Listeners {
			if l.TLS == nil {
				continue
			}

			for _, cert := range l.TLS.CertificateRefs {
				if !IsSecret(cert) {
					continue
				}
				ns := NamespaceDerefOr(cert.Namespace, gw.GetNamespace())
				if string(cert.Name) == obj.GetName() && ns == obj.GetNamespace() {
					gateways = append(gateways, &gw)
				}
			}
		}
	}
	return gateways
}
