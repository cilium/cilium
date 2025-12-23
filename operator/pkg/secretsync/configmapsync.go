// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	OwningConfigMapNamespace = "secretsync.cilium.io/owning-configmap-namespace"
	OwningConfigMapName      = "secretsync.cilium.io/owning-configmap-name"
)

// configMapSyncer syncs secrets to dedicated namespace.
type configMapSyncer struct {
	client client.Client
	logger *slog.Logger

	registrations    []*ConfigMapSyncRegistration
	secretNamespaces []string
	// Synchronized Secrets will resync after this time,
	// with some jitter (see jitterAmount)
	resyncInterval time.Duration
	// jitterAmount represents the fraction of the
	// resyncInterval that resyncs will be jittered
	// from the base interval.
	jitterAmount float64
}

type ConfigMapSyncRegistration struct {
	// RefObject defines the Kubernetes Object that is referencing a K8s Secret that needs to be synced.
	RefObject client.Object
	// RefObjectEnqueueFunc defines the mapping function from the reference object to the Secret.
	RefObjectEnqueueFunc handler.EventHandler
	// RefObjectCheckFunc defines a function that is called to check whether the given K8s Secret
	// is still referenced by a reference object.
	// Synced Secrets that origin from K8s Secrets that are no longer referenced by any registration are deleted.
	RefObjectCheckFunc func(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.ConfigMap) bool
	// SecretsNamespace defines the name of the namespace in which the referenced K8s Secrets are to be synchronized.
	SecretsNamespace string
	// AdditionalWatches defines additional watches beside watching the directly referencing Kubernetes Object.
	AdditionalWatches []AdditionalWatch
	// DefaultSecret defines an optional reference to a TLS Secret that should be synced regardless of whether it's referenced or not.
	DefaultSecret *DefaultSecret
}

func (r ConfigMapSyncRegistration) String() string {
	return fmt.Sprintf("%T -> %q", r.RefObject, r.SecretsNamespace)
}

func (r ConfigMapSyncRegistration) IsDefaultSecret(secret *corev1.Secret) bool {
	return r.DefaultSecret != nil && r.DefaultSecret.Namespace == secret.Namespace && r.DefaultSecret.Name == secret.Name
}

func NewConfigMapSyncReconciler(c client.Client, logger *slog.Logger, registrations []*ConfigMapSyncRegistration, resyncInterval time.Duration, jitterAmount float64) *configMapSyncer {
	regs := []*ConfigMapSyncRegistration{}
	secretNamespaces := []string{}
	for _, r := range registrations {
		if r != nil {
			regs = append(regs, r)
			secretNamespaces = append(secretNamespaces, r.SecretsNamespace)
		}
	}

	return &configMapSyncer{
		client: c,
		logger: logger,

		registrations:    regs,
		secretNamespaces: secretNamespaces,
		resyncInterval:   resyncInterval,
		jitterAmount:     jitterAmount,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *configMapSyncer) SetupWithManager(mgr ctrl.Manager) error {
	r.logger.Info("Setting up ConfigMap synchronization", logfields.Registrations, r.registrations)

	builder := ctrl.NewControllerManagedBy(mgr).
		// Source Secrets outside of the secrets namespace
		For(&corev1.ConfigMap{}).
		// Synced Secrets in the secrets namespace
		Watches(&corev1.Secret{}, enqueueOwningConfigMapFromLabels(), r.deletedOrChangedInSecretsNamespace())

	for _, r := range r.registrations {
		// Watch main object referencing TLS secrets
		builder = builder.Watches(r.RefObject, r.RefObjectEnqueueFunc)

		for _, a := range r.AdditionalWatches {
			builder = builder.Watches(a.RefObject, a.RefObjectEnqueueFunc, a.RefObjectWatchOptions...)
		}
	}

	return builder.Complete(r)
}

func (r *configMapSyncer) deletedOrChangedInSecretsNamespace() builder.Predicates {
	return builder.WithPredicates(&deletedOrChangedInSecretsNamespaceStruct{
		secretNamespaces: r.secretNamespaces,
	})
}

func (r *configMapSyncer) hasRegistrations() bool {
	return len(r.registrations) > 0
}

func enqueueOwningConfigMapFromLabels() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		labels := o.GetLabels()

		if labels == nil {
			return nil
		}

		owningConfigMapNamespace, owningConfigMapNamespacePresent := labels[OwningConfigMapNamespace]
		owningConfigMapName, owningConfigMapNamePresent := labels[OwningConfigMapName]

		if !owningConfigMapNamespacePresent || !owningConfigMapNamePresent {
			return nil
		}

		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: owningConfigMapNamespace,
					Name:      owningConfigMapName,
				},
			},
		}
	})
}
