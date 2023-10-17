// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	owningSecretName      = "io.cilium.gateway/owning-secret-name"
	owningSecretNamespace = "io.cilium.gateway/owning-secret-namespace"
)

// secretSyncer syncs Gateway API secrets to dedicated namespace.
type secretSyncer struct {
	client.Client
	Scheme *runtime.Scheme

	SecretsNamespace string
	controllerName   string
}

// SetupWithManager sets up the controller with the Manager.
func (r *secretSyncer) SetupWithManager(mgr ctrl.Manager) error {
	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, r.controllerName)
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, builder.WithPredicates(predicate.NewPredicateFuncs(r.usedInGateway))).
		Watches(&gatewayv1.Gateway{},
			r.enqueueRequestForGatewayTLS(),
			builder.WithPredicates(predicate.NewPredicateFuncs(hasMatchingControllerFn))).
		Complete(r)
}

func (r *secretSyncer) usedInGateway(obj client.Object) bool {
	return getGatewaysForSecret(context.Background(), r.Client, obj) != nil
}

func (r *secretSyncer) enqueueRequestForGatewayTLS() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "secrets",
			logfields.Resource:   obj.GetName(),
		})

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
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
				scopedLog.WithField("secret", s).Debug("Enqueued secret for gateway")
			}
		}
		return reqs
	})
}
