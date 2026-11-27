// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	syncnames "github.com/cilium/cilium/pkg/secretsync/names"
	"github.com/cilium/cilium/pkg/time"
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

// EnqueueFrontendTLSConfigMapsGateway produces a handler.EventHandler that, when it is passed a
// Gateway as the object.Object, returns any ConfigMaps referenced in the Frontend TLS validation.
func (h *SecretSyncHandler) EnqueueFrontendTLSConfigMapsGateway() handler.EventHandler {
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

		var reqs []reconcile.Request

		for cm := range helpers.FrontendTLSConfigMapRefSet(gw) {
			reqs = append(reqs, reconcile.Request{NamespacedName: cm})
			scopedLog.DebugContext(ctx, "Enqueued ConfigMap for Gateway frontend TLS validation",
				logfields.ConfigMapName, cm)
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
	scopedLog := logger.With(logfields.Resource, cfgMap.GetName())
	cfgMapKey := client.ObjectKeyFromObject(cfgMap)
	cfgMapNamespace := gatewayv1.Namespace(cfgMap.Namespace)

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

		refs := helpers.FrontendTLSConfigMapRefSet(gw)
		if _, ok := refs[cfgMapKey]; !ok {
			continue
		}

		if !helpers.IsReferenceAllowed(
			gw.Namespace,
			cfgMap.Name,
			&cfgMapNamespace,
			gatewayv1.SchemeGroupVersion.WithKind("Gateway"),
			corev1.SchemeGroupVersion.WithKind("ConfigMap"),
			grants.Items,
		) {
			continue
		}

		gateways = append(gateways, gw)
	}

	return gateways
}

func (h *SecretSyncHandler) EnqueueFrontendTLSConfigMapsReferenceGrant() handler.EventHandler {
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

			for cfgMap := range helpers.FrontendTLSConfigMapRefSet(gw) {
				// ReferenceGrants only matter for cross-namespace references,
				// and this grant can only affect references into its namespace.
				if cfgMap.Namespace == gw.Namespace || cfgMap.Namespace != grant.Namespace {
					continue
				}

				requests[reconcile.Request{NamespacedName: cfgMap}] = struct{}{}
			}
		}

		reqs := make([]reconcile.Request, 0, len(requests))
		for req := range requests {
			reqs = append(reqs, req)
		}
		return reqs
	})
}

const (
	sessionTicketKey              = "tls.sessionticket.key"
	sessionTicketRotatedAt        = "gateway.cilium.io/session-ticket-key-rotated-at"
	sessionTicketGatewayNamespace = "gateway.cilium.io/session-ticket-gateway-namespace"
	sessionTicketGatewayName      = "gateway.cilium.io/session-ticket-gateway-name"
)

type sessionTicketReconciler struct {
	client           client.Client
	logger           *slog.Logger
	namespace        string
	rotationInterval time.Duration
	clock            clock.PassiveClock
}

func (r *sessionTicketReconciler) setupWithManager(manager ctrl.Manager) error {
	r.clock = clock.RealClock{}
	return ctrl.NewControllerManagedBy(manager).
		Named("gateway-session-ticket-keys").
		For(&gatewayv1.Gateway{}).
		Watches(&gatewayv1.GatewayClass{}, watchhandlers.EnqueueRequestForOwningGatewayClass(r.client, *r.logger)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, object client.Object) []reconcile.Request {
			if object.GetNamespace() != r.namespace {
				return nil
			}
			annotations := object.GetAnnotations()
			if annotations[sessionTicketGatewayNamespace] == "" || annotations[sessionTicketGatewayName] == "" {
				return nil
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{
				Namespace: annotations[sessionTicketGatewayNamespace], Name: annotations[sessionTicketGatewayName],
			}}}
		})).
		Complete(r)
}

func (r *sessionTicketReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	gateway := &gatewayv1.Gateway{}
	if err := r.client.Get(ctx, request.NamespacedName, gateway); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if gateway.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}
	gatewayClass := &gatewayv1.GatewayClass{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, gatewayClass); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if gatewayClass.Spec.ControllerName != defaultControllerName {
		return reconcile.Result{}, nil
	}
	secretName := syncnames.GatewaySessionTicketSecretName(gateway.UID)
	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: r.namespace, Name: secretName}, secret)
	if err != nil && !k8serrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	now := r.clock.Now()
	if err == nil {
		rotatedAt, err := time.Parse(time.RFC3339Nano, secret.Annotations[sessionTicketRotatedAt])
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("invalid session ticket rotation time: %w", err)
		}
		if len(secret.Data[sessionTicketKey]) != 80 {
			return reconcile.Result{}, errors.New("managed session ticket key must contain exactly 80 bytes")
		}
		if remaining := rotatedAt.Add(r.rotationInterval).Sub(now); remaining > 0 {
			return reconcile.Result{RequeueAfter: remaining}, nil
		}
	}
	key := make([]byte, 80)
	rand.Read(key)
	data := map[string][]byte{sessionTicketKey: key}
	if previous := secret.Data[sessionTicketKey]; len(previous) > 0 {
		data[sessionTicketKey+".1"] = previous
	}
	secret.Data = data
	secret.Type = corev1.SecretTypeOpaque
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[sessionTicketRotatedAt] = now.Format(time.RFC3339Nano)
	secret.Annotations[sessionTicketGatewayNamespace] = gateway.Namespace
	secret.Annotations[sessionTicketGatewayName] = gateway.Name
	if k8serrors.IsNotFound(err) {
		secret.Name = secretName
		secret.Namespace = r.namespace
		err = r.client.Create(ctx, secret)
	} else {
		err = r.client.Update(ctx, secret)
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: r.rotationInterval}, nil
}
