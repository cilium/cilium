// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

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
	logger *slog.Logger

	registrations    []*SecretSyncRegistration
	secretNamespaces []string
}

type SecretSyncRegistration struct {
	// RefObject defines the Kubernetes Object that is referencing a K8s Secret that needs to be synced.
	RefObject client.Object
	// RefObjectEnqueueFunc defines the mapping function from the reference object to the Secret.
	RefObjectEnqueueFunc handler.EventHandler
	// RefObjectCheckFunc defines a function that is called to check whether the given K8s Secret
	// is still referenced by a reference object.
	// Synced Secrets that origin from K8s Secrets that are no longer referenced by any registration are deleted.
	RefObjectCheckFunc func(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool
	// SecretsNamespace defines the name of the namespace in which the referenced K8s Secrets are to be synchronized.
	SecretsNamespace string
	// AdditionalWatches defines additional watches beside watching the directly referencing Kubernetes Object.
	AdditionalWatches []AdditionalWatch
	// DefaultSecret defines an optional reference to a TLS Secret that should be synced regardless of whether it's referenced or not.
	DefaultSecret *DefaultSecret
}

type AdditionalWatch struct {
	RefObject             client.Object
	RefObjectEnqueueFunc  handler.EventHandler
	RefObjectWatchOptions []builder.WatchesOption
}

type DefaultSecret struct {
	Namespace string
	Name      string
}

func (r SecretSyncRegistration) String() string {
	return fmt.Sprintf("%T -> %q", r.RefObject, r.SecretsNamespace)
}

func (r SecretSyncRegistration) IsDefaultSecret(secret *corev1.Secret) bool {
	return r.DefaultSecret != nil && r.DefaultSecret.Namespace == secret.Namespace && r.DefaultSecret.Name == secret.Name
}

func NewSecretSyncReconciler(c client.Client, logger *slog.Logger, registrations []*SecretSyncRegistration) *secretSyncer {
	regs := []*SecretSyncRegistration{}
	secretNamespaces := []string{}
	for _, r := range registrations {
		if r != nil {
			regs = append(regs, r)
			secretNamespaces = append(secretNamespaces, r.SecretsNamespace)
		}
	}

	return &secretSyncer{
		client: c,
		logger: logger,

		registrations:    regs,
		secretNamespaces: secretNamespaces,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *secretSyncer) SetupWithManager(mgr ctrl.Manager) error {
	r.logger.Info("Setting up Secret synchronization", "registrations", r.registrations)

	builder := ctrl.NewControllerManagedBy(mgr).
		// Source Secrets outside of the secrets namespace
		For(&corev1.Secret{}, r.notInSecretsNamespace()).
		// Synced Secrets in the secrets namespace
		Watches(&corev1.Secret{}, enqueueOwningSecretFromLabels(), r.deletedOrChangedInSecretsNamespace())

	for _, r := range r.registrations {
		// Watch main object referencing TLS secrets
		builder = builder.Watches(r.RefObject, r.RefObjectEnqueueFunc)

		for _, a := range r.AdditionalWatches {
			builder = builder.Watches(a.RefObject, a.RefObjectEnqueueFunc, a.RefObjectWatchOptions...)
		}
	}

	return builder.Complete(r)
}

func (r *secretSyncer) notInSecretsNamespace() builder.Predicates {
	return builder.WithPredicates(predicate.NewPredicateFuncs(func(object client.Object) bool {
		return !slices.Contains(r.secretNamespaces, object.GetNamespace())
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
		secretNamespaces: r.secretNamespaces,
	})
}

func (r *secretSyncer) hasRegistrations() bool {
	return len(r.registrations) > 0
}

var _ predicate.Predicate = &deletedOrChangedInSecretsNamespaceStruct{}

type deletedOrChangedInSecretsNamespaceStruct struct {
	secretNamespaces []string
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Create(event.CreateEvent) bool {
	return false
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Update(event event.UpdateEvent) bool {
	return slices.Contains(r.secretNamespaces, event.ObjectOld.GetNamespace())
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Delete(event event.DeleteEvent) bool {
	return slices.Contains(r.secretNamespaces, event.Object.GetNamespace())
}

func (r *deletedOrChangedInSecretsNamespaceStruct) Generic(event.GenericEvent) bool {
	return false
}
