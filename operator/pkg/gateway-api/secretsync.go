// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func EnqueueTLSSecrets(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return nil
		}

		// Check whether Gateway is managed by Cilium
		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			return nil
		}

		var reqs []reconcile.Request
		for _, l := range gw.Spec.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, cert := range l.TLS.CertificateRefs {
				if !helpers.IsSecret(cert) {
					continue
				}
				s := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(cert.Namespace, gw.Namespace),
					Name:      string(cert.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: s})
				scopedLog.DebugContext(ctx, "Enqueued secret for gateway", logfields.Secret, s)
			}
		}
		return reqs
	})
}

func IsReferencedByCiliumGateway(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool {
	gateways := getGatewaysForSecret(ctx, c, obj, logger)
	for _, gw := range gateways {
		if hasMatchingController(ctx, c, controllerName, logger)(gw) {
			return true
		}
	}

	return false
}

// Enqueue BackendTLSPolicyConfigmaps produces a handler.EventHandler that, when it is passed a
// BackendTLSPolicy as the object.Object, returns any ConfigMaps referenced.
func EnqueueBackendTLSPolicyConfigMaps(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)

		var reqs []reconcile.Request

		btlsp, ok := obj.(*gatewayv1.BackendTLSPolicy)
		if !ok {
			return nil
		}

		for _, certRef := range btlsp.Spec.Validation.CACertificateRefs {
			if !helpers.IsConfigMap(certRef) {
				continue
			}
			c := types.NamespacedName{
				Namespace: btlsp.GetNamespace(),
				Name:      string(certRef.Name),
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: c})
			scopedLog.DebugContext(ctx, "Enqueued configmap for backendtlspolicy", logfields.ConfigMap, c)
		}
		return reqs
	})
}

func ConfigMapIsReferencedInCiliumGateway(ctx context.Context, c client.Client, logger *slog.Logger, cfgMap *corev1.ConfigMap) bool {
	scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-backendtlspolicy-configmap")

	cfgMapName := types.NamespacedName{
		Name:      cfgMap.GetName(),
		Namespace: cfgMap.GetNamespace(),
	}

	// Fetch all BackendTLSPolicies that reference this ConfigMap
	btlspList := &gatewayv1.BackendTLSPolicyList{}

	if err := c.List(ctx, btlspList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.BackendTLSPolicyConfigMapIndex, cfgMapName.String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Failed to get related BackendTLSPolicies for ConfigMap", logfields.Error, err)
		return false
	}
	// If there are no relevant BackendTLSPolicies, then we can skip this ConfigMap.
	if len(btlspList.Items) == 0 {
		return false
	}

	for _, btlsp := range btlspList.Items {
		for _, ancestorStatus := range btlsp.Status.Ancestors {
			// An Ancestor Status with the Cilium controller name and Accepted: True is only added by Cilium if
			// everything is good, so we are covered.
			if ancestorStatus.ControllerName == controllerName && helpers.IsAccepted(ancestorStatus.Conditions) {
				return true
			}
		}
	}
	return false
}
