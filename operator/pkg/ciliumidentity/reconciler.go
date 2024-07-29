// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type reconciler struct {
	logger          *slog.Logger
	ctx             context.Context
	clientset       k8sClient.Clientset
	idAllocator     *basicallocator.BasicIDAllocator
	desiredCIDState *CIDState
	cidUsageInPods  *CIDUsageInPods
	cidUsageInCES   *CIDUsageInCES
	// Ensures no CID duplicates are created while allocating CIDs in parallel,
	// (that is, when processing a pod event and a CID event concurrently).
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
) (*reconciler, error) {
	logger.Info("Creating CID controller Operator reconciler")

	minIDValue := idpool.ID(identity.GetMinimalAllocationIdentity(option.Config.ClusterID))
	maxIDValue := idpool.ID(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))
	idAllocator := basicallocator.NewBasicIDAllocator(minIDValue, maxIDValue)

	nsStore, err := namespace.Store(ctx)
	if err != nil {
		return nil, err
	}
	podStore, err := pod.Store(ctx)
	if err != nil {
		return nil, err
	}
	cidStore, err := ciliumIdentity.Store(ctx)
	if err != nil {
		return nil, err
	}
	cepStore, err := ciliumEndpoint.Store(ctx)
	if err != nil {
		return nil, err
	}
	cesStore, err := ciliumEndpointSlice.Store(ctx)
	if err != nil {
		return nil, err
	}

	r := &reconciler{
		logger:          logger,
		ctx:             ctx,
		clientset:       clientset,
		idAllocator:     idAllocator,
		desiredCIDState: NewCIDState(logger),
		cidUsageInPods:  NewCIDUsageInPods(),
		cidUsageInCES:   NewCIDUsageInCES(),
		queueOps:        queueOps,
		nsStore:         nsStore,
		podStore:        podStore,
		cidStore:        cidStore,
		cepStore:        cepStore,
		cesStore:        cesStore,
		cesEnabled:      cesEnabled,
	}

	return r, nil
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

// syncPodsOnStartup ensures that all pods have a CID for their labels.
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
// 2. Creates CID - If CID only exists in the desired state cache.
// 3. Updates CID - If CIDs in the desired state cache and watcher's store are
// not the same.
// Currently, the CID deletion is handled by the operator/identitygc
func (r *reconciler) reconcileCID(cidResourceKey resource.Key) error {
	cidName := cidResourceKey.Name
	storeCID, existsInStore, err := r.cidStore.GetByKey(cidResourceKey)

	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}

	cidKey, existsInDesiredState := r.desiredCIDState.LookupByID(cidName)
	if !existsInDesiredState && !existsInStore {
		err := r.makeIDAvailable(cidName)
		r.logger.Warn("Failed to return CID to pool",
			logfields.CIDName, cidName,
			logfields.Error, err)
		return nil
	}

	cidIsUsed := r.cidIsUsedInPods(cidName) || r.cidIsUsedInCEPOrCES(cidName)

	if !existsInDesiredState {
		if !cidIsUsed {
			return nil
		}

		r.cidCreateLock.Lock()
		defer r.cidCreateLock.Unlock()

		id, err := r.idAllocator.ValidateIDString(cidName)
		if err != nil {
			return err
		}
		return r.idAllocator.Allocate(idpool.ID(id))
	}

	if !existsInStore {
		if cidIsUsed {
			return r.createCID(cidName, cidKey)
		} else {
			r.desiredCIDState.Remove(cidName)
			return nil
		}
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

	_, err := r.clientset.CiliumV2().CiliumIdentities().Create(r.ctx, cid, metav1.CreateOptions{})
	return err
}

func (r *reconciler) updateCID(cid *cilium_api_v2.CiliumIdentity, cidKey *key.GlobalIdentity) error {
	cidLabels := cidKey.GetAsMap()
	selectedLabels, skippedLabels := identitybackend.SanitizeK8sLabels(cidLabels)
	r.logger.Debug("Skipped non-kubernetes labels when labelling CID. All labels will still be used in identity determination", logfields.Labels, skippedLabels)

	cid.Labels = selectedLabels
	cid.SecurityLabels = cidLabels

	r.logger.Info("Updating CID", logfields.CIDName, cid.Name)

	_, err := r.clientset.CiliumV2().CiliumIdentities().Update(r.ctx, cid, metav1.UpdateOptions{})
	return err
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
// created for new unique label sets.
func (r *reconciler) reconcilePod(podKey resource.Key) error {
	pod, exists, err := r.podStore.GetByKey(podKey)
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	// When a pod is not found in the pod store, it means it's deleted.
	if !exists {
		_, _, _ = r.cidUsageInPods.RemovePod(podKey.String())
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
	prevCIDName, _ := r.cidUsageInPods.AssignCIDToPod(podName, cidName)

	if cidName != prevCIDName {
		r.logger.Info("CID allocated for pod",
			logfields.K8sPodName, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
			logfields.CIDName, cidName,
			logfields.OldIdentity, prevCIDName,
			logfields.Labels, k8sLabels)
	}

	if isNewCID {
		r.queueOps.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
	}

	return nil
}

func (r *reconciler) allocateCID(cidKey *key.GlobalIdentity) (string, bool, error) {
	cidName, exists := r.desiredCIDState.LookupByKey(cidKey)
	if exists {
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
	ns, exists, err := r.nsStore.GetByKey(resource.Key{Name: namespace})
	if err != nil {
		return nil, fmt.Errorf("unable to get namespace %q, error: %w", namespace, err)
	}
	if !exists {
		return nil, fmt.Errorf("namespace %q not found in store", namespace)
	}

	return ns, nil
}

func (r *reconciler) handleStoreCIDMatch(storeCIDs []*cilium_api_v2.CiliumIdentity) (string, error) {
	// Deduplication: The first cid will be added to the desired cache
	cid := storeCIDs[0]
	cidKey := key.GetCIDKeyFromLabels(cid.SecurityLabels, "")

	if err := r.upsertDesiredState(cid.Name, cidKey); err != nil {
		r.logger.Warn("Failed to add CID to cache",
			logfields.CIDName, cid.Name,
			logfields.Error, err)
		return "", err
	} else {
		return cid.Name, nil
	}
}

// reconcileNamespace enqueues all pods in the namespace to be reconciled by the CID
// controller.
func (r *reconciler) reconcileNamespace(nsKey resource.Key) error {
	if err := r.updateAllPodsInNamespace(nsKey.Name); err != nil {
		return fmt.Errorf("reconcile namespace %s change: %w", nsKey.Name, err)
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
