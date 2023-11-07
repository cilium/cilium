// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	OwningSecretNamespace = "secretsync.cilium.io/owning-secret-namespace"
	OwningSecretName      = "secretsync.cilium.io/owning-secret-name"
)

// secretSyncer syncs secrets to dedicated namespace.
type secretSyncer struct {
	client client.Client
	logger logrus.FieldLogger

	mainObject               client.Object
	mainObjectEnqueueFunc    handler.EventHandler
	mainObjectReferencedFunc func(ctx context.Context, c client.Client, obj *corev1.Secret) bool
	secretsNamespace         string
}

func NewSecretSyncReconciler(c client.Client, logger logrus.FieldLogger, mainObject client.Object, mainObjectEnqueueFunc handler.EventHandler, mainObjectReferencedFunc func(ctx context.Context, c client.Client, obj *corev1.Secret) bool, secretsNamespace string) *secretSyncer {
	return &secretSyncer{
		client: c,
		logger: logger,

		mainObject:               mainObject,
		mainObjectEnqueueFunc:    mainObjectEnqueueFunc,
		mainObjectReferencedFunc: mainObjectReferencedFunc,
		secretsNamespace:         secretsNamespace,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *secretSyncer) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Source Secrets outside of the secrets namespace
		For(&corev1.Secret{}, r.notInSecretsNamespace()).
		// Synced Secrets in the secrets namespace
		Watches(&corev1.Secret{}, enqueueOwningSecretFromLabels(), r.deletedOrChangedInSecretsNamespace()).
		// Watch main object referencing TLS secrets
		Watches(r.mainObject, r.mainObjectEnqueueFunc).
		Complete(r)
}

func (r *secretSyncer) notInSecretsNamespace() builder.Predicates {
	return builder.WithPredicates(predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetNamespace() != r.secretsNamespace
	}))
}

func enqueueOwningSecretFromLabels() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		labels := o.GetLabels()

		if labels == nil {
			return nil
		}

		owningSecretNamespace, owningSecretNamespacePresent := labels[OwningSecretNamespace]
		owningSecretName, owningSecretNamePresent := labels[OwningSecretName]

		if !owningSecretNamespacePresent || !owningSecretNamePresent {
			return nil
		}

		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: owningSecretNamespace,
					Name:      owningSecretName,
				},
			},
		}
	})
}

func (r *secretSyncer) deletedOrChangedInSecretsNamespace() builder.Predicates {
	return builder.WithPredicates(&deletedOrChangedInSecretsNamespaceStruct{
		secretsNamespace: r.secretsNamespace,
	})
}

var _ predicate.Predicate = &deletedOrChangedInSecretsNamespaceStruct{}

type deletedOrChangedInSecretsNamespaceStruct struct {
	secretsNamespace string
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Create(event.CreateEvent) bool {
	return false
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Update(event event.UpdateEvent) bool {
	return event.ObjectOld.GetNamespace() == r.secretsNamespace
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Delete(event event.DeleteEvent) bool {
	return event.Object.GetNamespace() == r.secretsNamespace
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Generic(event.GenericEvent) bool {
	return false
}
