// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *secretSyncer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "secret-syncer",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling secret")

	original := &corev1.Secret{}
	if err := r.client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.WithError(err).Debug("Unable to get Secret - either deleted or not yet available")

			synced := false
			// Check whether synced secret needs to be deleted from the registered secret namespaces.
			for _, ns := range r.secretNamespaces {
				// Check if there's an existing synced secret for the deleted Secret
				deleted, err := r.cleanupSyncedSecret(ctx, req, scopedLog, ns)
				if err != nil {
					return controllerruntime.Fail(err)
				}

				synced = synced || deleted
			}

			scopedLog.WithField(logfields.Action, action(synced)).Info("Successfully reconciled Secret")
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(err)
	}

	cleanupNamespaces := map[string]struct{}{}
	for _, ns := range r.secretNamespaces {
		cleanupNamespaces[ns] = struct{}{}
	}

	synced := false
	for _, reg := range r.registrations {
		if reg.RefObjectCheckFunc(ctx, r.client, r.logger, original) || reg.IsDefaultSecret(original) {
			desiredSync := desiredSyncSecret(reg.SecretsNamespace, original)

			scopedLog.WithField("secretNamespace", reg.SecretsNamespace).Debug("Syncing secret")
			if err := r.ensureSyncedSecret(ctx, desiredSync); err != nil {
				return controllerruntime.Fail(err)
			}

			synced = true
			delete(cleanupNamespaces, reg.SecretsNamespace)
		}
	}

	// Check whether synced secret needs to be deleted from the secret namespaces
	// where the secret is no longer referenced by any registration.
	for ns := range cleanupNamespaces {
		// Check if there's an existing synced secret that should be deleted
		deleted, err := r.cleanupSyncedSecret(ctx, req, scopedLog, ns)
		if err != nil {
			return controllerruntime.Fail(err)
		}
		synced = synced || deleted
	}

	scopedLog.WithField(logfields.Action, action(synced)).Info("Successfully reconciled Secret")
	return controllerruntime.Success()
}

func action(synced bool) string {
	action := "ignored"
	if synced {
		action = "synced"
	}

	return action
}

func (r *secretSyncer) cleanupSyncedSecret(ctx context.Context, req reconcile.Request, scopedLog *logrus.Entry, ns string) (bool, error) {
	syncSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: ns, Name: req.Namespace + "-" + req.Name}, syncSecret); err == nil {
		// Try to delete existing synced secret
		scopedLog.WithField("secretNamespace", ns).Debug("Delete synced secret")
		if err := r.client.Delete(ctx, syncSecret); err != nil {
			return true, err
		}

		return true, nil
	}

	return false, nil
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
	s.Labels[OwningSecretNamespace] = original.Namespace
	s.Labels[OwningSecretName] = original.Name
	s.Immutable = original.Immutable
	s.Data = original.Data
	s.StringData = original.StringData
	s.Type = original.Type

	return s
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
