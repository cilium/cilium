// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/spanstat"
)

// ruleImportMetadataCache maps the unique identifier of a CiliumNetworkPolicy
// (namespace and name) to metadata about the importing of the rule into the
// agent's policy repository at the time said rule was imported (revision
// number, and if any error occurred while importing).
type ruleImportMetadataCache struct {
	mutex                 lock.RWMutex
	ruleImportMetadataMap map[string]policyImportMetadata
}

type policyImportMetadata struct {
	revision          uint64
	policyImportError error
}

func (r *ruleImportMetadataCache) upsert(cnp *types.SlimCNP, revision uint64, importErr error) {
	if cnp == nil {
		return
	}

	meta := policyImportMetadata{
		revision:          revision,
		policyImportError: importErr,
	}
	podNSName := k8sUtils.GetObjNamespaceName(&cnp.ObjectMeta)

	r.mutex.Lock()
	r.ruleImportMetadataMap[podNSName] = meta
	r.mutex.Unlock()
}

func (r *ruleImportMetadataCache) delete(cnp *types.SlimCNP) {
	if cnp == nil {
		return
	}
	podNSName := k8sUtils.GetObjNamespaceName(&cnp.ObjectMeta)

	r.mutex.Lock()
	delete(r.ruleImportMetadataMap, podNSName)
	r.mutex.Unlock()
}

func (r *ruleImportMetadataCache) get(cnp *types.SlimCNP) (policyImportMetadata, bool) {
	if cnp == nil {
		return policyImportMetadata{}, false
	}
	podNSName := k8sUtils.GetObjNamespaceName(&cnp.ObjectMeta)
	r.mutex.RLock()
	policyImportMeta, ok := r.ruleImportMetadataMap[podNSName]
	r.mutex.RUnlock()
	return policyImportMeta, ok
}

func (k *K8sWatcher) ciliumNetworkPoliciesInit(ctx context.Context, cs client.Clientset) {
	var hasSynced atomic.Bool
	apiGroup := k8sAPIGroupCiliumNetworkPolicyV2
	metricLabel := resources.MetricCNP
	go func() {
		cache := make(map[resource.Key]*types.SlimCNP)

		for event := range k.sharedResources.CiliumNetworkPolicies.Events(ctx) {
			if event.Kind == resource.Sync {
				hasSynced.Store(true)
				event.Done(nil)
				continue
			}

			slimCNP := &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta:   event.Object.TypeMeta,
					ObjectMeta: event.Object.ObjectMeta,
					Spec:       event.Object.Spec,
					Specs:      event.Object.Specs,
				},
			}

			var err error
			switch event.Kind {
			case resource.Upsert:
				err = k.onUpsertCNP(slimCNP, cache, event.Key, cs, apiGroup, metricLabel)
			case resource.Delete:
				err = k.onDeleteCNP(slimCNP, cache, event.Key, apiGroup, metricLabel)
			}
			reportCNPChangeMetrics(err)
			event.Done(err)
		}
	}()

	k.blockWaitGroupToSyncResources(ctx.Done(), nil, hasSynced.Load, apiGroup)
	k.k8sAPIGroups.AddAPI(apiGroup)
}

func (k *K8sWatcher) onUpsertCNP(
	cnp *types.SlimCNP,
	cache map[resource.Key]*types.SlimCNP,
	key resource.Key,
	cs client.Clientset,
	apiGroup string,
	metricLabel string,
) error {
	initialRecvTime := time.Now()

	var (
		equal  bool
		action string
	)

	// wrap k.K8sEventReceived call into a naked func() to capture equal in the closure
	defer func() {
		k.K8sEventReceived(apiGroup, metricLabel, action, true, equal)
	}()

	oldCNP, ok := cache[key]
	if !ok {
		action = resources.MetricCreate
	} else {
		action = resources.MetricUpdate
		if oldCNP.DeepEqual(cnp) {
			equal = true
			return nil
		}
	}

	if cnp.RequiresDerivative() {
		return nil
	}

	// We need to deepcopy this structure because we are writing
	// fields.
	// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
	cnpCpy := cnp.DeepCopy()

	var err error
	if ok {
		err = k.updateCiliumNetworkPolicyV2(cs, oldCNP, cnpCpy, initialRecvTime)
	} else {
		err = k.addCiliumNetworkPolicyV2(cs, cnpCpy, initialRecvTime)
	}
	if err == nil {
		cache[key] = cnpCpy
	}

	k.K8sEventProcessed(metricLabel, action, err == nil)

	return err
}

func (k *K8sWatcher) onDeleteCNP(
	cnp *types.SlimCNP,
	cache map[resource.Key]*types.SlimCNP,
	key resource.Key,
	apiGroup string,
	metricLabel string,
) error {
	err := k.deleteCiliumNetworkPolicyV2(cnp)
	delete(cache, key)

	k.K8sEventProcessed(metricLabel, resources.MetricDelete, err == nil)
	k.K8sEventReceived(apiGroup, metricLabel, resources.MetricDelete, true, true)

	return err
}

func (k *K8sWatcher) addCiliumNetworkPolicyV2(ciliumNPClient clientset.Interface, cnp *types.SlimCNP, initialRecvTime time.Time) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	var rev uint64

	rules, policyImportErr := cnp.Parse()
	if policyImportErr == nil {
		policyImportErr = k8s.PreprocessRules(rules, &k.K8sSvcCache)
		// Replace all rules with the same name, namespace and
		// resourceTypeCiliumNetworkPolicy
		if policyImportErr == nil {
			rev, policyImportErr = k.policyManager.PolicyAdd(rules, &policy.AddOptions{
				ReplaceWithLabels:   cnp.GetIdentityLabels(),
				Source:              metrics.LabelEventSourceK8s.Name,
				ProcessingStartTime: initialRecvTime,
			})
		}
	}

	if policyImportErr != nil {
		metrics.PolicyImportErrorsTotal.Inc() // Deprecated in Cilium 1.14, to be removed in 1.15.
		scopedLog.WithError(policyImportErr).Warn("Unable to add CiliumNetworkPolicy")
	} else {
		scopedLog.Info("Imported CiliumNetworkPolicy")
	}

	// Upsert to rule revision cache outside of controller, because upsertion
	// *must* be synchronous so that if we get an update for the CNP, the cache
	// is populated by the time updateCiliumNetworkPolicyV2 is invoked.
	importMetadataCache.upsert(cnp, rev, policyImportErr)

	if !option.Config.DisableCNPStatusUpdates {
		updateContext := &k8s.CNPStatusUpdateContext{
			CiliumNPClient:              ciliumNPClient,
			NodeName:                    nodeTypes.GetName(),
			NodeManager:                 k.nodeDiscoverManager,
			UpdateDuration:              spanstat.Start(),
			WaitForEndpointsAtPolicyRev: k.endpointManager.WaitForEndpointsAtPolicyRev,
		}

		ctrlName := cnp.GetControllerName()
		k8sCM.UpdateController(ctrlName,
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) error {
					return updateContext.UpdateStatus(ctx, cnp, rev, policyImportErr)
				},
			},
		)
	}

	return policyImportErr
}

func (k *K8sWatcher) deleteCiliumNetworkPolicyV2(cnp *types.SlimCNP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Deleting CiliumNetworkPolicy")

	importMetadataCache.delete(cnp)
	ctrlName := cnp.GetControllerName()
	err := k8sCM.RemoveControllerAndWait(ctrlName)
	if err != nil {
		log.WithError(err).Debugf("Unable to remove controller %s", ctrlName)
	}

	_, err = k.policyManager.PolicyDelete(cnp.GetIdentityLabels())
	if err == nil {
		scopedLog.Info("Deleted CiliumNetworkPolicy")
	} else {
		scopedLog.WithError(err).Warn("Unable to delete CiliumNetworkPolicy")
	}
	return err
}

func (k *K8sWatcher) updateCiliumNetworkPolicyV2(ciliumNPClient clientset.Interface,
	oldRuleCpy, newRuleCpy *types.SlimCNP, initialRecvTime time.Time) error {

	_, err := oldRuleCpy.Parse()
	if err != nil {
		ns := oldRuleCpy.GetNamespace() // Disambiguates CNP & CCNP

		// We want to ignore parsing errors for empty policies, otherwise the
		// update to the new policy will be skipped.
		switch {
		case ns != "" && !errors.Is(err, cilium_v2.ErrEmptyCNP):
			metrics.PolicyImportErrorsTotal.Inc() // Deprecated in Cilium 1.14, to be removed in 1.15.
			log.WithError(err).WithField(logfields.Object, logfields.Repr(oldRuleCpy)).
				Warn("Error parsing old CiliumNetworkPolicy rule")
			return err
		case ns == "" && !errors.Is(err, cilium_v2.ErrEmptyCCNP):
			metrics.PolicyImportErrorsTotal.Inc() // Deprecated in Cilium 1.14, to be removed in 1.15.
			log.WithError(err).WithField(logfields.Object, logfields.Repr(oldRuleCpy)).
				Warn("Error parsing old CiliumClusterwideNetworkPolicy rule")
			return err
		}
	}

	_, err = newRuleCpy.Parse()
	if err != nil {
		metrics.PolicyImportErrorsTotal.Inc() // Deprecated in Cilium 1.14, to be removed in 1.15.
		log.WithError(err).WithField(logfields.Object, logfields.Repr(newRuleCpy)).
			Warn("Error parsing new CiliumNetworkPolicy rule")
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                    oldRuleCpy.TypeMeta.APIVersion,
		logfields.CiliumNetworkPolicyName + ".old": oldRuleCpy.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":            oldRuleCpy.ObjectMeta.Namespace,
		logfields.CiliumNetworkPolicyName:          newRuleCpy.ObjectMeta.Name,
		logfields.K8sNamespace:                     newRuleCpy.ObjectMeta.Namespace,
		"annotations.old":                          oldRuleCpy.ObjectMeta.Annotations,
		"annotations":                              newRuleCpy.ObjectMeta.Annotations,
	}).Debug("Modified CiliumNetworkPolicy")

	// Do not add rule into policy repository if the spec remains unchanged.
	if !option.Config.DisableCNPStatusUpdates {
		if oldRuleCpy.Spec.DeepEqual(newRuleCpy.CiliumNetworkPolicy.Spec) &&
			oldRuleCpy.Specs.DeepEqual(&newRuleCpy.CiliumNetworkPolicy.Specs) {
			if !oldRuleCpy.AnnotationsEquals(newRuleCpy.CiliumNetworkPolicy) {

				// Update annotations within a controller so the status of the update
				// is trackable from the list of running controllers, and so we do
				// not block subsequent policy lifecycle operations from Kubernetes
				// until the update is complete.
				oldCtrlName := oldRuleCpy.GetControllerName()
				newCtrlName := newRuleCpy.GetControllerName()

				// In case the controller name changes between copies of rules,
				// remove old controller so we do not leak goroutines.
				if oldCtrlName != newCtrlName {
					err := k8sCM.RemoveController(oldCtrlName)
					if err != nil {
						log.WithError(err).Debugf("Unable to remove controller %s", oldCtrlName)
					}
				}
				k.updateCiliumNetworkPolicyV2AnnotationsOnly(ciliumNPClient, newRuleCpy)
			}
			return nil
		}
	}

	return k.addCiliumNetworkPolicyV2(ciliumNPClient, newRuleCpy, initialRecvTime)
}

func (k *K8sWatcher) updateCiliumNetworkPolicyV2AnnotationsOnly(ciliumNPClient clientset.Interface, cnp *types.SlimCNP) {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Info("updating node status due to annotations-only change to CiliumNetworkPolicy")

	ctrlName := cnp.GetControllerName()

	// Revision will *always* be populated because importMetadataCache is guaranteed
	// to be updated by addCiliumNetworkPolicyV2 before calls to
	// updateCiliumNetworkPolicyV2 are invoked.
	meta, _ := importMetadataCache.get(cnp)
	updateContext := &k8s.CNPStatusUpdateContext{
		CiliumNPClient:              ciliumNPClient,
		NodeName:                    nodeTypes.GetName(),
		NodeManager:                 k.nodeDiscoverManager,
		UpdateDuration:              spanstat.Start(),
		WaitForEndpointsAtPolicyRev: k.endpointManager.WaitForEndpointsAtPolicyRev,
	}

	k8sCM.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return updateContext.UpdateStatus(ctx, cnp, meta.revision, meta.policyImportError)
			},
		})

}

// reportCNPChangeMetrics generates metrics for changes (Add, Update, Delete) to
// Cilium Network Policies depending on the operation's success.
func reportCNPChangeMetrics(err error) {
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail.Name).Inc()
	} else {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess.Name).Inc()
	}
}
