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

func (h *SecretSyncHandler) EnqueueListenerSetTLSSecrets() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := h.logger.With(
			logfields.Resource, obj.GetName(),
		)

		ls, ok := obj.(*gatewayv1.ListenerSet)
		if !ok {
			return nil
		}

		gw := &gatewayv1.Gateway{}
		gwNN := helpers.ListenerSetParentGateway(ls)
		if err := h.client.Get(ctx, *gwNN, gw); err != nil {
			scopedLog.DebugContext(ctx, "Unable to get parent gateway for listenerset", logfields.Error, err)
			return nil
		}

		// Check whether parent Gateway is managed by Cilium
		if !helpers.GatewayHasMatchingControllerFn(ctx, h.client, h.controllerName, h.logger)(gw) {
			return nil
		}

		var reqs []reconcile.Request
		for _, l := range ls.Spec.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, cert := range l.TLS.CertificateRefs {
				if !helpers.IsSecret(cert) {
					continue
				}
				s := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(cert.Namespace, ls.Namespace),
					Name:      string(cert.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: s})
				scopedLog.DebugContext(ctx, "Enqueued secret for listenerset", logfields.Secret, s)
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
		scopedLog := h.logger.With(logfields.Resource, obj.GetName())

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return nil
		}

		// Check whether Gateway is managed by Cilium
		if !helpers.GatewayHasMatchingControllerFn(ctx, h.client, h.controllerName, h.logger)(gw) {
			return nil
		}

		frontend := helpers.FrontendTLSConfig(gw)

		if frontend == nil {
			return nil
		}

		var reqs []reconcile.Request

		if frontend.Default.Validation != nil {
			if certRef, ok := helpers.FirstFrontendTLSCACertificateRef(frontend.Default.Validation); ok &&
				helpers.IsObjectRefConfigMap(certRef) {
				cm := types.NamespacedName{
					Namespace: helpers.NamespaceDerefOr(certRef.Namespace, gw.Namespace),
					Name:      string(certRef.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: cm})
				scopedLog.DebugContext(ctx, "Enqueued ConfigMap for Gateway default frontend TLS validation", logfields.ConfigMapName, cm)
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
				scopedLog.DebugContext(ctx, "Enqueued ConfigMap for Gateway per-port frontend TLS validation", logfields.ConfigMapName, cm)
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

func (h *SecretSyncHandler) EnqueueConfigMapsForFrontendTLSReferenceGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		grant, ok := obj.(*gatewayv1.ReferenceGrant)
		if !ok {
			return nil
		}

		gwList := &gatewayv1.GatewayList{}
		if err := h.client.List(ctx, gwList); err != nil {
			h.logger.ErrorContext(ctx, "Failed to list Gateways for ReferenceGrant change", logfields.Error, err)
			return nil
		}

		requests := map[reconcile.Request]struct{}{}

		for i := range gwList.Items {
			gw := &gwList.Items[i]

			if !helpers.GatewayHasMatchingControllerFn(ctx, h.client, h.controllerName, h.logger)(gw) {
				continue
			}

			enqueue := func(validation *gatewayv1.FrontendTLSValidation) {
				ref, ok := helpers.FirstFrontendTLSCACertificateRef(validation)
				if !ok || !helpers.IsObjectRefConfigMap(ref) {
					return
				}

				refNamespace := helpers.NamespaceDerefOr(ref.Namespace, gw.Namespace)

				// ReferenceGrants only matter for cross-namespace references,
				// and this grant can only affect references into its namespace.
				if refNamespace == gw.Namespace || refNamespace != grant.Namespace {
					return
				}

				requests[reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: refNamespace,
						Name:      string(ref.Name),
					},
				}] = struct{}{}
			}

			if gw.Spec.TLS != nil && gw.Spec.TLS.Frontend != nil {
				frontend := gw.Spec.TLS.Frontend

				enqueue(frontend.Default.Validation)

				for _, perPort := range frontend.PerPort {
					enqueue(perPort.TLS.Validation)
				}
			}
		}

		reqs := make([]reconcile.Request, 0, len(requests))
		for req := range requests {
			reqs = append(reqs, req)
		}
		return reqs
	})
}

// getGatewaysForFrontendTLSConfigMap returns all Gateways that reference the given ConfigMap
// in their frontend TLS validation configuration.
func getGatewaysForFrontendTLSConfigMap(ctx context.Context, c client.Client, cfgMap *corev1.ConfigMap, logger *slog.Logger) []*gatewayv1.Gateway {
	scopedLog := logger.With(logfields.Resource, cfgMap.GetName())

	gwList := &gatewayv1.GatewayList{}
	if err := c.List(ctx, gwList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Gateways", logfields.Error, err)
		return nil
	}

	grants := &gatewayv1.ReferenceGrantList{}
	if err := c.List(ctx, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list ReferenceGrants", logfields.Error, err)
		return nil
	}

	var gateways []*gatewayv1.Gateway
	for i := range gwList.Items {
		gw := &gwList.Items[i]
		frontend := helpers.FrontendTLSConfig(gw)

		if frontend == nil {
			continue
		}

		if frontend.Default.Validation != nil {
			if frontendTLSValidationConfigMapMatches(frontend.Default.Validation, gw.Namespace, grants.Items, cfgMap) {
				gateways = append(gateways, gw)
				continue
			}
		}

		for _, perPort := range frontend.PerPort {
			if perPort.TLS.Validation == nil {
				continue
			}
			if frontendTLSValidationConfigMapMatches(perPort.TLS.Validation, gw.Namespace, grants.Items, cfgMap) {
				gateways = append(gateways, gw)
				break
			}
		}
	}

	return gateways
}

func frontendTLSValidationConfigMapMatches(
	validation *gatewayv1.FrontendTLSValidation,
	gatewayNamespace string,
	grants []gatewayv1.ReferenceGrant,
	cfgMap *corev1.ConfigMap,
) bool {
	certRef, ok := helpers.FirstFrontendTLSCACertificateRef(validation)
	if !ok || !helpers.IsObjectRefConfigMap(certRef) {
		return false
	}

	refNs := helpers.NamespaceDerefOr(certRef.Namespace, gatewayNamespace)
	if refNs != cfgMap.Namespace || string(certRef.Name) != cfgMap.Name {
		return false
	}

	return refNs == gatewayNamespace || helpers.IsObjectRefAllowed(
		gatewayNamespace,
		certRef,
		gatewayv1.SchemeGroupVersion.WithKind("Gateway"),
		corev1.SchemeGroupVersion.WithKind("ConfigMap"),
		grants,
	)
}
