// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crdhelpers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"syscall"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// needsStorageMigration returns true if the CRD in question may need its
// versions migrated.
//
// CRD's have a Status field that list all (potentially) stored versionss.
// This is the list of any versions that have *ever* been set as stored, and is
// maintained by the apiserver.
// A migration is required if the current CRD spec has fewer stored
// versions than the CRD's Status.
func CRDNeedsMigration(crd *apiextensionsv1.CustomResourceDefinition) bool {
	// Get the set of stored versions as understood by the APIServer -- these are the set
	// that may exist in storage.
	specStoredVersions := sets.New(crd.Status.StoredVersions...)

	// Delete all versions currently marked as stored - we don't need to migrate them
	for _, ver := range crd.Spec.Versions {
		if ver.Storage {
			specStoredVersions.Delete(ver.Name)
		}
	}

	// We will need a migration if there is a stored version not listed as stored in the CRD spec
	return specStoredVersions.Len() > 0
}

// List chunk size
const chunkSize = 500

// MigrateStorageVersion performs a storage version migration of the given CRD.
//
// To do this, we issue a no-op PATCH request against all existing objects. This
// will trigger the apiserver to migrate the stored version. Once all objects have
// been patched, we can remove any obsolete stored versions from the CRD Status field.
//
// See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/
func MigrateStorageVersion(ctx context.Context, log *slog.Logger, clientset k8sClient.Clientset, crdName string) error {
	log = log.With(logfields.Resource, crdName)

	var crd *apiextensionsv1.CustomResourceDefinition
	err := transientRetry(log, ctx, func() error {
		var err error
		crd, err = clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crdName, metav1.GetOptions{})
		return err
	})
	if err != nil {
		return err
	}
	if !CRDNeedsMigration(crd) {
		return nil
	}

	gvr := schema.GroupVersionResource{
		Group:    crd.Spec.Group,
		Resource: crd.Spec.Names.Plural,
	}
	// pick the first served + stored version to use for the patch resource
	for _, ver := range crd.Spec.Versions {
		if !ver.Storage || !ver.Served {
			continue
		}
		gvr.Version = ver.Name
		break
	}
	// not possible; version must be stored + served
	if gvr.Version == "" {
		return nil
	}

	log = log.With(logfields.Version, gvr.Version)
	log.Info("CRD version migration: listing existing objects")

	// List all objects, using a paged lister.
	objs := []types.NamespacedName{}
	listContinue := ""
	for {
		log.Debug("listing objects",
			logfields.Remaining, listContinue)

		var l *unstructured.UnstructuredList
		listErr := transientRetry(log, ctx, func() error {
			var err error
			l, err = clientset.Resource(gvr).List(ctx,
				metav1.ListOptions{
					Limit:    chunkSize,
					Continue: listContinue,
				})
			return err
		})
		if listErr != nil {
			// pagination stumbled, need to restart
			if apierrors.IsResourceExpired(listErr) {
				listContinue = ""
				log.Info("List continue expired, retrying", logfields.Error, err)
				continue
			}

			log.Warn("Failed to list existing objects", logfields.Error, err)
			return fmt.Errorf("failed to list %s for storage migration: %w", crd.Name, listErr)
		}

		for _, obj := range l.Items {
			objs = append(objs, types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()})
		}

		listContinue = l.GetContinue()
		if listContinue == "" {
			// paging complete
			break
		}
	}

	log.Info("Migrating existing objects", logfields.Count, len(objs))

	for _, nsn := range objs {
		log := log.With(
			logfields.K8sNamespace, nsn.Namespace,
			logfields.Name, nsn.Name)
		log.Debug("Issuing no-op patch")

		patchErr := transientRetry(log, ctx, func() error {
			_, err := clientset.Resource(gvr).Namespace(nsn.Namespace).Patch(
				ctx,
				nsn.Name,
				types.MergePatchType,
				[]byte(`{}`),
				metav1.PatchOptions{},
			)
			return err
		})
		if patchErr != nil {
			// Object was deleted - nothing to do
			if apierrors.IsNotFound(patchErr) {
				continue
			}

			log.Warn("No-op patch request failed",
				logfields.Error, patchErr)
			return fmt.Errorf("failed to patch %s %s/%s: %w", crd.Name, nsn.Namespace, nsn.Name, patchErr)
		}
	}

	log.Info("All objects migrated, removing obsolete CRD storage version references from status")

	origStatusVersions := crd.Status.StoredVersions

	// Remove all non-spec stored versions from the Status
	err = transientRetry(log, ctx, func() error {
		crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crdName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		// paranoia: something changed during migration
		if !slices.Equal(origStatusVersions, crd.Status.StoredVersions) {
			log.Warn("CRD was updated during storage migration, not touching stored version")
			return fmt.Errorf("CRD was updated during storage migration")
		}

		storedVersions := []string{}
		for _, version := range crd.Spec.Versions {
			if version.Storage {
				storedVersions = append(storedVersions, version.Name)
			}
		}

		crd = crd.DeepCopy()
		crd.Status.StoredVersions = storedVersions
		_, err = clientset.ApiextensionsV1().CustomResourceDefinitions().UpdateStatus(ctx, crd, metav1.UpdateOptions{})
		return err
	})
	if err != nil && !apierrors.IsNotFound(err) {
		log.Warn("Failed to update CRD .Status.StoredVersions", logfields.Error, err)
		return fmt.Errorf("failed to update CRD %s .Status.StoredVersions : %w", crdName, err)
	}

	log.Info("CRD version migration complete.")
	return nil
}

// isTransientError returns true if the error is temporary and retryable
// (network issues, API server overload), vs permanent errors (CRD not installed).
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Kubernetes API server errors that are transient
	if apierrors.IsServerTimeout(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsConflict(err) {
		return true
	}

	// Check for network-level errors (connection refused, reset, host unreachable)
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		switch errno {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
			return true
		}
	}

	return false
}

const retries = 10

// transientRetry retries the given function until no error
// or a non-transient error is returned
func transientRetry(log *slog.Logger, ctx context.Context, f func() error) error {
	var err error
	delaySecs := 1
	for range retries {
		err = f()
		if err == nil {
			return nil
		}
		if !isTransientError(err) {
			return err
		}

		log.Debug("API request failed with transient error, will retry", logfields.Error, err)

		// delay more if the apiserver suggests it
		s, _ := apierrors.SuggestsClientDelay(err)
		delaySecs = max(delaySecs, s)

		ch := time.After(time.Second * time.Duration(delaySecs))
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}

		delaySecs *= 2
	}
	return err
}
