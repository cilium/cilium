// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForFrontendTLSConfigMap returns reconcile requests for Cilium
// Gateways that reference the changed ConfigMap in frontend TLS validation.
func EnqueueRequestForFrontendTLSConfigMap(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		cfgMap, ok := o.(*corev1.ConfigMap)
		if !ok {
			return nil
		}

		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-frontend-tls-configmap")

		gwList := &gatewayv1.GatewayList{}
		if err := c.List(ctx, gwList); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to list Gateways", logfields.Error, err)
			return nil
		}

		reconcileRequests := make(map[reconcile.Request]struct{})
		for i := range gwList.Items {
			gw := &gwList.Items[i]
			if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
				continue
			}
			if !frontendTLSConfigMapMatches(gw, cfgMap) {
				continue
			}
			reconcileRequests[reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: gw.GetNamespace(),
					Name:      gw.GetName(),
				},
			}] = struct{}{}
		}

		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.DebugContext(ctx, "Frontend TLS ConfigMap relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return recs
	})
}

func frontendTLSConfigMapMatches(gw *gatewayv1.Gateway, cfgMap *corev1.ConfigMap) bool {
	if gw.Spec.TLS == nil || gw.Spec.TLS.Frontend == nil {
		return false
	}

	frontend := gw.Spec.TLS.Frontend
	if frontend.Default.Validation != nil {
		if ref, ok := helpers.FirstFrontendTLSCACertificateRef(frontend.Default.Validation); ok &&
			configMapRefMatchesGateway(ref, gw.Namespace, cfgMap) {
			return true
		}
	}

	for _, perPort := range frontend.PerPort {
		if perPort.TLS.Validation == nil {
			continue
		}
		if ref, ok := helpers.FirstFrontendTLSCACertificateRef(perPort.TLS.Validation); ok &&
			configMapRefMatchesGateway(ref, gw.Namespace, cfgMap) {
			return true
		}
	}

	return false
}

func configMapRefMatchesGateway(ref gatewayv1.ObjectReference, defaultNamespace string, cfgMap *corev1.ConfigMap) bool {
	if !helpers.IsObjectRefConfigMap(ref) {
		return false
	}
	refNs := helpers.NamespaceDerefOr(ref.Namespace, defaultNamespace)
	return refNs == cfgMap.Namespace && string(ref.Name) == cfgMap.Name
}
