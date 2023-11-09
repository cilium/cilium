// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func EnqueueReferencedTLSSecrets(c client.Client, logger logrus.FieldLogger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.WithFields(logrus.Fields{
			logfields.Controller: "secrets",
			logfields.Resource:   obj.GetName(),
		})

		ing, ok := obj.(*networkingv1.Ingress)
		if !ok {
			return nil
		}

		// Check whether Ingress is managed by Cilium
		if !isCiliumManagedIngress(ctx, c, *ing) {
			return nil
		}

		var reqs []reconcile.Request
		for _, tls := range ing.Spec.TLS {
			if len(tls.SecretName) == 0 {
				continue
			}

			s := types.NamespacedName{
				Namespace: ing.Namespace,
				Name:      tls.SecretName,
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: s})
			scopedLog.WithField("secret", s).Debug("Enqueued secret for Ingress")
		}
		return reqs
	})
}

func enqueueAllSecrets(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		secretList := &corev1.SecretList{}
		if err := c.List(ctx, secretList); err != nil {
			return nil
		}

		requests := []reconcile.Request{}
		for _, s := range secretList.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: s.GetNamespace(),
					Name:      s.GetName(),
				},
			})
		}

		return requests
	})
}

func IsReferencedByCiliumIngress(ctx context.Context, c client.Client, obj *corev1.Secret) bool {
	ingresses := networkingv1.IngressList{}
	if err := c.List(ctx, &ingresses, client.InNamespace(obj.GetNamespace())); err != nil {
		return false
	}

	for _, i := range ingresses.Items {
		if isCiliumManagedIngress(ctx, c, i) {
			for _, t := range i.Spec.TLS {
				if t.SecretName == obj.GetName() {
					return true
				}
			}
		}
	}

	return false
}
