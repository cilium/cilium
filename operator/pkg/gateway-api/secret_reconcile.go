// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
	if err := r.client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.WithError(err).Debug("Unable to get Secret - either deleted or not yet available")

			// Check if there's an existing synced secret for the deleted Secret
			if err := r.cleanupSyncedSecret(ctx, req, scopedLog); err != nil {
				return fail(err)
			}

			// there is nothing to copy, the related gateway is not accepted anyway.
			// if later the secret is created, the gateway will be reconciled again,
			// then this secret will be copied.
			return success()
		}

		return fail(err)
	}

	if !r.isUsedByCiliumGateway(ctx, original) {
		// Check if there's an existing synced secret that should be deleted
		if err := r.cleanupSyncedSecret(ctx, req, scopedLog); err != nil {
			return fail(err)
		}
		return success()
	}

	desiredSync := desiredSyncSecret(r.secretsNamespace, original)

	if err := r.ensureSyncedSecret(ctx, desiredSync); err != nil {
		return fail(err)
	}

	scopedLog.Info("Successfully synced secrets")
	return success()
}

func (r *secretSyncer) cleanupSyncedSecret(ctx context.Context, req reconcile.Request, scopedLog *logrus.Entry) error {
	syncSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: r.secretsNamespace, Name: req.Namespace + "-" + req.Name}, syncSecret); err == nil {
		// Try to delete existing synced secret
		scopedLog.Debug("Delete synced secret")
		if err := r.client.Delete(ctx, syncSecret); err != nil {
			return err
		}
	}

	return nil
}

func desiredSyncSecret(secretsNamespace string, original *corev1.Secret) *corev1.Secret {
	s := &corev1.Secret{}
	s.SetNamespace(secretsNamespace)
	s.SetName(original.Namespace + "-" + original.Name)
	s.SetAnnotations(original.GetAnnotations())
	s.SetLabels(original.GetLabels())
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	s.Labels[owningSecretNamespace] = original.Namespace
	s.Labels[owningSecretName] = original.Name
	s.Immutable = original.Immutable
	s.Data = original.Data
	s.StringData = original.StringData
	s.Type = original.Type

	return s
}

func (r *secretSyncer) isUsedByCiliumGateway(ctx context.Context, obj *corev1.Secret) bool {
	gateways := getGatewaysForSecret(ctx, r.client, obj)
	for _, gw := range gateways {
		if hasMatchingController(ctx, r.client, r.controllerName)(gw) {
			return true
		}
	}

	return false
}

func (r *secretSyncer) ensureSyncedSecret(ctx context.Context, desired *corev1.Secret) error {
	existing := &corev1.Secret{}
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
		if k8serrors.IsNotFound(err) {
			return r.client.Create(ctx, desired)
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

	return r.client.Patch(ctx, temp, client.MergeFrom(existing))
}
