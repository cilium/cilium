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

type SecretSyncHandler struct {
	client         client.Client
	logger         *slog.Logger
	controllerName string
}

func NewSecretSyncHandler(c client.Client, logger *slog.Logger, controllerName string) *SecretSyncHandler {
	return &SecretSyncHandler{
		client:         c,
		logger:         logger,
		controllerName: controllerName,
	}
}

func (h *SecretSyncHandler) EnqueueTLSSecrets() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := h.logger.With(
			logfields.Resource, obj.GetName(),
		)

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return nil
		}

		// Check whether Gateway is managed by Cilium
		if !helpers.GatewayHasMatchingControllerFn(ctx, h.client, h.controllerName, h.logger)(gw) {
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

func (h *SecretSyncHandler) IsReferencedByGateway(ctx context.Context, _ client.Client, _ *slog.Logger, obj *corev1.Secret) bool {
	return len(helpers.GetGatewaysForSecret(ctx, h.client, obj, h.controllerName, h.logger)) > 0
}

// Enqueue BackendTLSPolicyConfigmaps produces a handler.EventHandler that, when it is passed a
// BackendTLSPolicy as the object.Object, returns any ConfigMaps referenced.
func (h *SecretSyncHandler) EnqueueBackendTLSPolicyConfigMaps() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := h.logger.With(
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
			cfg := types.NamespacedName{
				Namespace: btlsp.GetNamespace(),
				Name:      string(certRef.Name),
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: cfg})
			scopedLog.DebugContext(ctx, "Enqueued configmap for backendtlspolicy", logfields.ConfigMapName, cfg)
		}
		return reqs
	})
}

func (h *SecretSyncHandler) ConfigMapIsReferencedInGateway(ctx context.Context, _ client.Client, _ *slog.Logger, cfgMap *corev1.ConfigMap) bool {
	scopedLog := h.logger.With(logfields.LogSubsys, "queue-gw-from-backendtlspolicy-configmap")

	cfgMapName := client.ObjectKeyFromObject(cfgMap)

	// Fetch all BackendTLSPolicies that reference this ConfigMap
	btlspList := &gatewayv1.BackendTLSPolicyList{}

	if err := h.client.List(ctx, btlspList, &client.ListOptions{
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
			if string(ancestorStatus.ControllerName) == h.controllerName && helpers.IsAccepted(ancestorStatus.Conditions) {
				return true
			}
		}
	}
	return false
}

// EnqueueFrontendTLSConfigMaps produces a handler.EventHandler that, when it is passed a
// Gateway as the object.Object, returns any ConfigMaps referenced in the Frontend TLS validation.
func (h *SecretSyncHandler) EnqueueFrontendTLSConfigMaps() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := h.logger.With(
			logfields.Resource, obj.GetName(),
		)

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return nil
		}

		// Check whether Gateway is managed by Cilium
		if !helpers.GatewayHasMatchingControllerFn(ctx, h.client, h.controllerName, h.logger)(gw) {
			return nil
		}

		var reqs []reconcile.Request

		if gw.Spec.TLS == nil || gw.Spec.TLS.Frontend == nil {
			return nil
		}

		frontend := gw.Spec.TLS.Frontend

		if frontend.Default.Validation != nil {
			if certRef, ok := helpers.FirstFrontendTLSCACertificateRef(frontend.Default.Validation); ok &&
				helpers.IsObjectRefConfigMap(certRef) {
				cm := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(certRef.Namespace, gw.Namespace),
					Name:      string(certRef.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: cm})
				scopedLog.DebugContext(ctx, "Enqueued configmap for gateway frontend TLS", logfields.ConfigMapName, cm)
			}
		}

		for _, perPort := range frontend.PerPort {
			if perPort.TLS.Validation == nil {
				continue
			}
			if certRef, ok := helpers.FirstFrontendTLSCACertificateRef(perPort.TLS.Validation); ok &&
				helpers.IsObjectRefConfigMap(certRef) {
				cm := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(certRef.Namespace, gw.Namespace),
					Name:      string(certRef.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: cm})
				scopedLog.DebugContext(ctx, "Enqueued configmap for gateway frontend TLS per-port", logfields.ConfigMapName, cm)
			}
		}

		return reqs
	})
}

// FrontendTLSConfigMapIsReferenced checks if a ConfigMap is referenced by any Cilium Gateway's
// frontend TLS validation configuration.
func (h *SecretSyncHandler) FrontendTLSConfigMapIsReferenced(ctx context.Context, _ client.Client, _ *slog.Logger, cfgMap *corev1.ConfigMap) bool {
	gateways := getGatewaysForFrontendTLSConfigMap(ctx, h.client, cfgMap, h.logger)
	for _, gw := range gateways {
		if helpers.GatewayHasMatchingControllerFn(ctx, h.client, h.controllerName, h.logger)(gw) {
			return true
		}
	}
	return false
}

// getGatewaysForFrontendTLSConfigMap returns all Gateways that reference the given ConfigMap
// in their frontend TLS validation configuration.
func getGatewaysForFrontendTLSConfigMap(ctx context.Context, c client.Client, cfgMap *corev1.ConfigMap, logger *slog.Logger) []*gatewayv1.Gateway {
	scopedLog := logger.With(
		logfields.Resource, cfgMap.GetName(),
	)

	gwList := &gatewayv1.GatewayList{}
	if err := c.List(ctx, gwList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Gateways", logfields.Error, err)
		return nil
	}

	var gateways []*gatewayv1.Gateway
	for i := range gwList.Items {
		gw := &gwList.Items[i]
		if gw.Spec.TLS == nil || gw.Spec.TLS.Frontend == nil {
			continue
		}

		frontend := gw.Spec.TLS.Frontend

		if frontend.Default.Validation != nil {
			if certRef, ok := helpers.FirstFrontendTLSCACertificateRef(frontend.Default.Validation); ok {
				refNs := helpers.NamespaceDerefOr(certRef.Namespace, gw.Namespace)
				if refNs == cfgMap.Namespace && string(certRef.Name) == cfgMap.Name {
					gateways = append(gateways, gw)
				}
			}
		}

		for _, perPort := range frontend.PerPort {
			if perPort.TLS.Validation == nil {
				continue
			}
			if certRef, ok := helpers.FirstFrontendTLSCACertificateRef(perPort.TLS.Validation); ok {
				refNs := helpers.NamespaceDerefOr(certRef.Namespace, gw.Namespace)
				if refNs == cfgMap.Namespace && string(certRef.Name) == cfgMap.Name {
					gateways = append(gateways, gw)
				}
			}
		}
	}

	return gateways
}
