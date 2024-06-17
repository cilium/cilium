// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/cilium/pkg/labels"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	operator_k8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/basicallocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type reconciler struct {
	logger             *slog.Logger
	clientset          k8sClient.Clientset
	idAllocator        *basicallocator.BasicIDAllocator
	desiredCIDState    *CIDState
	cidUsageInPods     *CIDUsageInPods
	cidUsageInCES      *CIDUsageInCES
	cidDeletionTracker *CIDDeletionTracker
	// Ensures no CID duplicates are created while allocating CIDs in parallel,
	// and avoids race conditions when CIDs are being deleted.
	cidCreateLock lock.RWMutex
	cesEnabled    bool
	queueOps      queueOperations

	nsStore  resource.Store[*slim_corev1.Namespace]
	podStore resource.Store[*slim_corev1.Pod]
	cidStore resource.Store[*cilium_api_v2.CiliumIdentity]
	cepStore resource.Store[*cilium_api_v2.CiliumEndpoint]
	cesStore resource.Store[*v2alpha1.CiliumEndpointSlice]
}

func newReconciler(
	ctx context.Context,
	logger *slog.Logger,
	clientset k8sClient.Clientset,
	namespace resource.Resource[*slim_corev1.Namespace],
	pod resource.Resource[*slim_corev1.Pod],
	ciliumIdentity resource.Resource[*cilium_api_v2.CiliumIdentity],
	ciliumEndpoint resource.Resource[*cilium_api_v2.CiliumEndpoint],
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice],
	cesEnabled bool,
	queueOps queueOperations,
) *reconciler {
	logger.Info("Creating CID controller Operator reconciler")

	minIDValue := idpool.ID(identity.GetMinimalAllocationIdentity(option.Config.ClusterID))
	maxIDValue := idpool.ID(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))
	idAllocator := basicallocator.NewBasicIDAllocator(minIDValue, maxIDValue)

	nsStore, _ := namespace.Store(ctx)
	podStore, _ := pod.Store(ctx)
	cidStore, _ := ciliumIdentity.Store(ctx)
	cepStore, _ := ciliumEndpoint.Store(ctx)
	cesStore, _ := ciliumEndpointSlice.Store(ctx)

	r := &reconciler{
		logger:             logger,
		clientset:          clientset,
		idAllocator:        idAllocator,
		desiredCIDState:    NewCIDState(logger),
		cidUsageInPods:     NewCIDUsageInPods(),
		cidUsageInCES:      NewCIDUsageInCES(),
		cidDeletionTracker: NewCIDDeletionTracker(logger),
		queueOps:           queueOps,
		nsStore:            nsStore,
		podStore:           podStore,
		cidStore:           cidStore,
		cepStore:           cepStore,
		cesStore:           cesStore,
		cesEnabled:         cesEnabled,
	}

	return r
}

// syncCESsOnStartup updates the cache of CID usage in CES for all the
// existing CESs.
func (r *reconciler) calcDesiredStateOnStartup() error {
	r.syncCESsOnStartup()
	return r.syncPodsOnStartup()
}

func (r *reconciler) syncCESsOnStartup() {
	if !r.cesEnabled {
		return
	}

	for _, ces := range r.cesStore.List() {
		r.cidUsageInCES.ProcessCESUpsert(ces.Name, ces.Endpoints)
	}
}

// syncPodsOnStartup ensures that all pods have a CID for their labels, and that
// all non-used CIDs are deleted. Non used CIDs are those that aren't in use by
// any of the pods and also don't exist in CESs (if CES is enabled).
func (r *reconciler) syncPodsOnStartup() error {
	var lastError error

	for _, pod := range r.podStore.List() {
		if err := r.reconcilePod(podResourceKey(pod.Name, pod.Namespace)); err != nil {
			lastError = err
		}
	}

	return lastError
}

// reconcileCID ensures that the desired state for the CID is reached, by
// comparing the CID in desired state cache and watcher's store and doing one of
// the following:
// 1. Nothing - If CID doesn't exist in both desired state cache and watcher's
// store.
// 2. Deletes CID - If CID only exists in the watcher's store, and it isn't used.
// 3. Creates CID - If CID only exists in the desired state cache.
// 4. Updates CID - If CIDs in the desired state cache and watcher's store are
// not the same.
func (r *reconciler) reconcileCID(cidResourceKey resource.Key) error {
	cidName := cidResourceKey.Name
	storeCIDObj, existsInStore, err := r.cidStore.CacheStore().GetByKey(cidResourceKey.Name)

	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}

	var storeCID *cilium_api_v2.CiliumIdentity
	if existsInStore {
		var ok bool
		storeCID, ok = storeCIDObj.(*cilium_api_v2.CiliumIdentity)
		if !ok {
			return fmt.Errorf("wrong type (%T) of object when getting CID %q from the CID store", storeCIDObj, cidName)
		}
	}

	cidKey, existsInDesiredState := r.desiredCIDState.LookupByID(cidName)
	if !existsInDesiredState && !existsInStore {
		_ = r.makeIDAvailable(cidName)
		return nil
	}

	cidIsUsed := r.cidIsUsedInPods(cidName) || r.cidIsUsedInCEPOrCES(cidName)
	if !existsInDesiredState {
		if cidIsUsed {
			return nil
		}
		r.cidCreateLock.Lock()
		defer r.cidCreateLock.Unlock()
		return r.handleCIDDeletion(cidName)
	}

	if !cidIsUsed {
		if existsInStore {
			r.cidCreateLock.Lock()
			defer r.cidCreateLock.Unlock()
			return r.handleCIDDeletion(cidName)
		}

		r.desiredCIDState.Remove(cidName)
		return nil
	}

	if !existsInStore {
		return r.createCID(cidName, cidKey)
	}

	storeCIDKey := key.GetCIDKeyFromLabels(storeCID.SecurityLabels, "")
	if cidKey.Equals(storeCIDKey.LabelArray) {
		return nil
	}

	return r.updateCID(storeCID, cidKey)
}

func (r *reconciler) createCID(cidName string, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := identitybackend.SanitizeK8sLabels(cidLabels)
	r.logger.Debug("Skipped non-kubernetes labels when labelling CID. All labels will still be used in identity determination", logfields.Labels, skippedLabels)

	cid := &cilium_api_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   cidName,
			Labels: selectedLabels,
		},
		SecurityLabels: cidLabels,
	}

	r.logger.Info("Creating CID", "labels", cidLabels, logfields.CIDName, cidName)

	_, err := r.clientset.CiliumV2().CiliumIdentities().Create(context.TODO(), cid, metav1.CreateOptions{})
	return err
}

func (r *reconciler) updateCID(cid *cilium_api_v2.CiliumIdentity, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := identitybackend.SanitizeK8sLabels(cidLabels)
	r.logger.Debug("Skipped non-kubernetes labels when labelling CID. All labels will still be used in identity determination", logfields.Labels, skippedLabels)

	cid.Labels = selectedLabels
	cid.SecurityLabels = cidLabels

	r.logger.Info("Updating CID", logfields.CIDName, cid.Name)

	_, err := r.clientset.CiliumV2().CiliumIdentities().Update(context.TODO(), cid, metav1.UpdateOptions{})
	return err
}

func (r *reconciler) deleteCID(cidName string) error {
	r.logger.Info("Deleting CID", logfields.CIDName, cidName)

	err := r.clientset.CiliumV2().CiliumIdentities().Delete(context.TODO(), cidName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return nil
}

// handleCIDDeletion marks or deletes already marked CID.
// Requires to be called with cidCreateLock locked because it modifies the
// internal state of CID.
func (r *reconciler) handleCIDDeletion(cidName string) error {
	markedTime, isMarked := r.cidDeletionTracker.MarkedTime(cidName)
	if !isMarked {
		r.cidDeletionTracker.Mark(cidName)
		r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), cidDeleteDelay)
		return nil
	}

	durationSinceMarked := time.Since(markedTime)
	if durationSinceMarked >= cidDeleteDelay {
		if err := r.deleteCID(cidName); err != nil {
			r.logger.Error("Deleting CID failed, will retry", logfields.CIDName, cidName, logfields.Error, err)
			r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
			return fmt.Errorf("failed to delete CID: %w", err)
		}

		r.cidDeletionTracker.Unmark(cidName)
		r.desiredCIDState.Remove(cidName)
		r.makeIDAvailable(cidName)
		return nil
	}

	r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), cidDeleteDelay)
	return nil
}

func (r *reconciler) makeIDAvailable(cidName string) error {
	cidNum, err := strconv.Atoi(cidName)
	if err != nil {
		return err
	}
	return r.idAllocator.ReturnToAvailablePool(idpool.ID(cidNum))
}

func (r *reconciler) upsertDesiredState(cidName string, cidKey *key.GlobalIdentity) error {
	if cidKey == nil || len(cidName) == 0 {
		return fmt.Errorf("invalid CID, name: %q, key: %v", cidName, cidKey)
	}

	cachedCIDKey, exists := r.desiredCIDState.LookupByID(cidName)
	if exists && cidKey.Equals(cachedCIDKey.LabelArray) {
		return nil
	}

	id, err := r.idAllocator.ValidateIDString(cidName)
	if err != nil {
		return err
	}

	err = r.idAllocator.Allocate(idpool.ID(id))
	if err != nil {
		return err
	}
	r.desiredCIDState.Upsert(cidName, cidKey)

	return nil
}

// reconcilePod ensures that there is a CID that matches the pod. CIDs are
// created for new unique label sets, and potentially deleted when pods are
// deleted, if no other pods match the CID labels.
func (r *reconciler) reconcilePod(podKey resource.Key) error {
	pod, exists, err := r.podStore.GetByKey(podKey)
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	// When a pod is not found in the pod store, it means it's deleted.
	if !exists {
		prevCIDName, count, found := r.cidUsageInPods.RemovePod(podKey.String())
		if found && count == 0 && !r.cidIsUsedInCEPOrCES(prevCIDName) {
			r.cidCreateLock.Lock()
			defer r.cidCreateLock.Unlock()
			if e := r.handleCIDDeletion(prevCIDName); e != nil {
				r.logger.Error("CID deletion failed when reconciling pod deletion",
					logfields.CIDName, prevCIDName,
					logfields.K8sPodName, podKey.String(),
					logfields.Error, e)
			}
		}
		return nil
	}

	return r.allocateCIDForPod(pod)
}

func (r *reconciler) cidIsUsedInPods(cidName string) bool {
	return r.cidUsageInPods.CIDUsageCount(cidName) > 0
}

func (r *reconciler) cidIsUsedInCEPOrCES(cidName string) bool {
	if !r.cesEnabled {
		return operator_k8s.HasCEWithIdentity(r.cepStore, cidName)
	}

	cidUsageCount := r.cidUsageInCES.CIDUsageCount(cidName)
	return cidUsageCount > 0
}

// allocateCIDForPod gets pod and namespace labels that are relevant to security
// identities, and ensures that a CID exists for that label set.
// 1. CID exists: No action.
// 2. CID doesn't exist: Create CID.
func (r *reconciler) allocateCIDForPod(pod *slim_corev1.Pod) error {
	k8sLabels, err := r.getRelevantLabelsForPod(pod)
	if err != nil {
		return fmt.Errorf("failed to get relevant labels for pod: %w", err)
	}
	cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)

	r.cidCreateLock.Lock()
	defer r.cidCreateLock.Unlock()

	cidName, isNewCID, err := r.allocateCID(cidKey)
	if err != nil {
		return fmt.Errorf("failed to allocate CID: %w", err)
	}

	r.desiredCIDState.Upsert(cidName, cidKey)

	podName := podResourceKey(pod.Name, pod.Namespace).String()
	prevCIDName, count := r.cidUsageInPods.AssignCIDToPod(podName, cidName)

	r.logger.Info("CID allocated for pod",
		logfields.K8sPodName, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
		logfields.CIDName, cidName,
		logfields.OldIdentity, prevCIDName,
		logfields.Labels, k8sLabels)

	if len(prevCIDName) > 0 && count == 0 && !r.cidIsUsedInCEPOrCES(prevCIDName) {
		r.handleCIDDeletion(prevCIDName)
	}

	if isNewCID {
		r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
	}

	return nil
}

func (r *reconciler) allocateCID(cidKey *key.GlobalIdentity) (string, bool, error) {
	cidName, exists := r.desiredCIDState.LookupByKey(cidKey)
	if exists {
		r.cidDeletionTracker.Unmark(cidName)
		return cidName, false, nil
	}

	storeCIDs, err := r.cidStore.ByIndex(k8s.ByKeyIndex, cidKey.GetKey())
	if err != nil {
		return "", false, err
	}

	// If CIDs that match labels are found in CID store but not in the desired cache,
	// they need to be added to the desired cache and used instead of creating a new
	// CID for these labels.
	if len(storeCIDs) > 0 {
		// Return the assignment from the CID store, otherwise allocates a new identity
		cidName, err = r.handleStoreCIDMatch(storeCIDs)
		if err != nil {
			r.logger.Error("Failed to access CID store", logfields.Error, err)
		} else {
			r.cidDeletionTracker.Unmark(cidName)
			return cidName, false, nil
		}
	}

	allocatedID, err := r.idAllocator.AllocateRandom()
	if err != nil {
		return "", false, err
	}

	return allocatedID.String(), true, nil
}

func (r *reconciler) getRelevantLabelsForPod(pod *slim_corev1.Pod) (map[string]string, error) {
	ns, err := r.getNamespace(pod.Namespace)
	if err != nil {
		return nil, err
	}

	_, labelsMap, _, err := k8s.GetPodMetadata(ns, pod)
	if err != nil {
		return nil, err
	}

	return labelsMap, nil
}

func (r *reconciler) getNamespace(namespace string) (*slim_corev1.Namespace, error) {
	nsLookupObj := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}

	ns, exists, err := r.nsStore.Get(nsLookupObj)
	if err != nil {
		return nil, fmt.Errorf("unable to get namespace %q, error: %w", namespace, err)
	}
	if !exists {
		return nil, fmt.Errorf("namespace %q not found in store", namespace)
	}

	return ns, nil
}

func (r *reconciler) handleStoreCIDMatch(storeCIDs []*cilium_api_v2.CiliumIdentity) (string, error) {
	if len(storeCIDs) == 0 {
		return "", fmt.Errorf("store CIDs list is empty")
	}

	var selectedCIDName string

	// Deduplication: Reconcile all CID. The first will be added to the desired
	// cache and the rest will be deleted, because they are not used.
	for _, cid := range storeCIDs {
		toDelete := true

		if len(selectedCIDName) == 0 {
			cidKey := key.GetCIDKeyFromLabels(cid.SecurityLabels, "")
			if err := r.upsertDesiredState(cid.Name, cidKey); err != nil {
				r.logger.Warn("Failed to add CID to cache",
					logfields.CIDName, cid.Name,
					logfields.Error, err)
			} else {
				toDelete = false
				selectedCIDName = cid.Name
			}
		}

		if toDelete {
			r.queueOps.enqueueCIDReconciliation(cidResourceKey(cid.Name), 0)
		}
	}

	return selectedCIDName, nil
}

// reconcileNamespace enqueues all pods in the namespace to be reconciled by the CID
// controller.
func (r *reconciler) reconcileNamespace(nsKey resource.Key) error {
	if err := r.updateAllPodsInNamespace(nsKey.Name); err != nil {
		return fmt.Errorf("failed to reconcile namespace %s change: %w", nsKey.Name, err)
	}
	return nil
}

func (r *reconciler) updateAllPodsInNamespace(namespace string) error {
	r.logger.Info("Reconcile all pods in namespace", logfields.K8sNamespace, namespace)

	if r.podStore == nil {
		return fmt.Errorf("pod store is not initialized")
	}
	podList, err := r.podStore.ByIndex(cache.NamespaceIndex, namespace)
	if err != nil {
		return err
	}

	var lastErr error

	for _, pod := range podList {
		r.queueOps.enqueuePodReconciliation(podResourceKey(pod.Name, pod.Namespace), 0)
	}

	return lastErr
}
