// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/types"
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

	// Track which Gateways we've already added to avoid duplicates
	seen := make(map[types.NamespacedName]struct{})
	var gateways []*gatewayv1.Gateway

	for _, gw := range gwList.Items {
		for _, l := range gw.Spec.Listeners {
			if listenerReferencesSecret(l.TLS, gw.GetNamespace(), obj) {
				gwNN := types.NamespacedName{Name: gw.GetName(), Namespace: gw.GetNamespace()}
				if _, ok := seen[gwNN]; !ok {
					seen[gwNN] = struct{}{}
					gateways = append(gateways, &gw)
				}
				break
			}
		}
	}

	// Also scan ListenerSets for secret references
	if HasListenerSetSupport(c.Scheme()) {
		lsList := &gatewayv1.ListenerSetList{}
		if err := c.List(ctx, lsList); err != nil {
			scopedLog.WarnContext(ctx, "Unable to list ListenerSets", logfields.Error, err)
			return gateways
		}

		for _, ls := range lsList.Items {
			for _, entry := range ls.Spec.Listeners {
				if listenerReferencesSecret(entry.TLS, ls.GetNamespace(), obj) {
					gwNN := *ListenerSetParentGateway(&ls)
					if _, ok := seen[gwNN]; ok {
						break
					}
					seen[gwNN] = struct{}{}
					// Look up the actual Gateway object
					gw := &gatewayv1.Gateway{}
					if err := c.Get(ctx, gwNN, gw); err != nil {
						scopedLog.WarnContext(ctx, "Unable to get Gateway for ListenerSet", logfields.Error, err)
						break
					}
					gateways = append(gateways, gw)
					break
				}
			}
		}
	}

	return gateways
}

// listenerReferencesSecret checks if a listener's TLS config references the given secret.
func listenerReferencesSecret(tls *gatewayv1.ListenerTLSConfig, ownerNamespace string, secret client.Object) bool {
	if tls == nil {
		return false
	}
	for _, cert := range tls.CertificateRefs {
		if !IsSecret(cert) {
			continue
		}
		ns := NamespaceDerefOr(cert.Namespace, ownerNamespace)
		if string(cert.Name) == secret.GetName() && ns == secret.GetNamespace() {
			return true
		}
	}
	return false
}
