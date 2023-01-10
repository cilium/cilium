// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *secretSyncer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "secret-syncer",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Syncing secrets")

	original := &corev1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			// there is nothing to copy, the related gateway is not accepted anyway.
			// if later the secret is created, the gateway will be reconciled again,
			// then this secret will be copied.
			scopedLog.WithError(err).Warn("Unable to get Secret")
			return success()
		}
		return fail(err)
	}

	c := &corev1.Secret{}
	c.SetNamespace(r.SecretsNamespace)
	c.SetName(original.Namespace + "-" + original.Name)
	c.SetAnnotations(original.GetAnnotations())
	c.SetLabels(original.GetLabels())
	if c.Labels == nil {
		c.Labels = map[string]string{}
	}
	c.Labels[owningSecretNamespace] = original.Namespace
	c.Labels[owningSecretName] = original.Name
	c.Immutable = original.Immutable
	c.Data = original.Data
	c.StringData = original.StringData
	c.Type = original.Type

	if err := r.ensureSecret(ctx, c); err != nil {
		scopedLog.WithError(err).Error("Unable to sync secret")
		return fail(err)
	}

	scopedLog.Info("Successfully synced secrets")
	return success()
}

func (r *secretSyncer) ensureSecret(ctx context.Context, desired *corev1.Secret) error {
	existing := &corev1.Secret{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}

	temp := existing.DeepCopy()
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())
	temp.Immutable = desired.Immutable
	temp.Data = desired.Data
	temp.StringData = desired.StringData
	temp.Type = desired.Type

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}
