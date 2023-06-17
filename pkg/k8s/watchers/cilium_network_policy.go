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
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
	"github.com/cilium/cilium/pkg/source"
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
	var cnpSynced, ccnpSynced, cidrGroupSynced atomic.Bool
	go func() {
		cnpEvents := k.resources.CiliumNetworkPolicies.Events(ctx)
		ccnpEvents := k.resources.CiliumClusterwideNetworkPolicies.Events(ctx)

		// cnpCache contains both CNPs and CCNPs, stored using a common intermediate
		// representation (*types.SlimCNP). The cache is indexed on resource.Key,
		// that contains both the name and namespace of the resource, in order to
		// avoid key clashing between CNPs and CCNPs.
		// The cache contains CNPs and CCNPs in their "original form"
		// (i.e: pre-translation of each CIDRGroupRef to a CIDRSet).
		cnpCache := make(map[resource.Key]*types.SlimCNP)

		cidrGroupCache := make(map[string]*cilium_v2_alpha1.CiliumCIDRGroup)
		cidrGroupEvents := k.resources.CIDRGroups.Events(ctx)

		// cidrGroupPolicies is the set of policies that are referencing CiliumCIDRGroup objects.
		cidrGroupPolicies := make(map[resource.Key]struct{})

		for {
			select {
			case event, ok := <-cnpEvents:
				if !ok {
					cnpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					cnpSynced.Store(true)
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

				resourceID := ipcacheTypes.NewResourceID(
					ipcacheTypes.ResourceKindCNP,
					slimCNP.ObjectMeta.Namespace,
					slimCNP.ObjectMeta.Name,
				)
				var err error
				switch event.Kind {
				case resource.Upsert:
					err = k.onUpsert(slimCNP, cnpCache, event.Key, cidrGroupCache, cs, k8sAPIGroupCiliumNetworkPolicyV2, resources.MetricCNP, cidrGroupPolicies, resourceID)
				case resource.Delete:
					err = k.onDelete(slimCNP, cnpCache, event.Key, k8sAPIGroupCiliumNetworkPolicyV2, resources.MetricCNP, cidrGroupPolicies, resourceID)
				}
				reportCNPChangeMetrics(err)
				event.Done(err)
			case event, ok := <-ccnpEvents:
				if !ok {
					ccnpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					ccnpSynced.Store(true)
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

				resourceID := ipcacheTypes.NewResourceID(
					ipcacheTypes.ResourceKindCCNP,
					slimCNP.ObjectMeta.Namespace,
					slimCNP.ObjectMeta.Name,
				)
				var err error
				switch event.Kind {
				case resource.Upsert:
					err = k.onUpsert(slimCNP, cnpCache, event.Key, cidrGroupCache, cs, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, resources.MetricCCNP, cidrGroupPolicies, resourceID)
				case resource.Delete:
					err = k.onDelete(slimCNP, cnpCache, event.Key, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, resources.MetricCCNP, cidrGroupPolicies, resourceID)
				}
				reportCNPChangeMetrics(err)
				event.Done(err)
			case event, ok := <-cidrGroupEvents:
				if !ok {
					cidrGroupEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					cidrGroupSynced.Store(true)
					event.Done(nil)
					continue
				}

				var err error
				switch event.Kind {
				case resource.Upsert:
					err = k.onUpsertCIDRGroup(event.Object, cidrGroupCache, cnpCache, cs, k8sAPIGroupCiliumCIDRGroupV2Alpha1, resources.MetricCCG)
				case resource.Delete:
					err = k.onDeleteCIDRGroup(event.Object.Name, cidrGroupCache, cnpCache, cs, k8sAPIGroupCiliumCIDRGroupV2Alpha1, resources.MetricCCG)
				}
				event.Done(err)
			}
			if cnpEvents == nil && ccnpEvents == nil && cidrGroupEvents == nil {
				return
			}
		}
	}()

	k.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumNetworkPolicyV2, func() bool {
		return cnpSynced.Load() && cidrGroupSynced.Load()
	})
	k.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, func() bool {
		return ccnpSynced.Load() && cidrGroupSynced.Load()
	})
	k.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumCIDRGroupV2Alpha1, func() bool {
		return cidrGroupSynced.Load()
	})
}

func (k *K8sWatcher) onUpsert(
	cnp *types.SlimCNP,
	cnpCache map[resource.Key]*types.SlimCNP,
	key resource.Key,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cs client.Clientset,
	apiGroup string,
	metricLabel string,
	cidrGroupPolicies map[resource.Key]struct{},
	resourceID ipcacheTypes.ResourceID,
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

	oldCNP, ok := cnpCache[key]
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

	// check if this cnp was referencing or is now referencing a
	// CiliumCIDRGroup and update the relevant metric accordingly.
	if len(getCIDRGroupRefs(cnp)) > 0 {
		cidrGroupPolicies[key] = struct{}{}
	} else {
		delete(cidrGroupPolicies, key)
	}
	metrics.CIDRGroupPolicies.Set(float64(len(cidrGroupPolicies)))

	// We need to deepcopy this structure because we are writing
	// fields.
	// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
	cnpCpy := cnp.DeepCopy()

	translationStart := time.Now()
	translatedCNP := resolveCIDRGroupRef(cnpCpy, cidrGroupCache)
	metrics.CIDRGroupTranslationTimeStats.Observe(time.Since(translationStart).Seconds())

	var err error
	if ok {
		err = k.updateCiliumNetworkPolicyV2(cs, oldCNP, translatedCNP, initialRecvTime, resourceID)
	} else {
		err = k.addCiliumNetworkPolicyV2(cs, translatedCNP, initialRecvTime, resourceID)
	}
	if err == nil {
		cnpCache[key] = cnpCpy
	}

	k.K8sEventProcessed(metricLabel, action, err == nil)

	return err
}

func (k *K8sWatcher) onDelete(
	cnp *types.SlimCNP,
	cache map[resource.Key]*types.SlimCNP,
	key resource.Key,
	apiGroup string,
	metricLabel string,
	cidrGroupPolicies map[resource.Key]struct{},
	resourceID ipcacheTypes.ResourceID,
) error {
	err := k.deleteCiliumNetworkPolicyV2(cnp, resourceID)
	delete(cache, key)

	delete(cidrGroupPolicies, key)
	metrics.CIDRGroupPolicies.Set(float64(len(cidrGroupPolicies)))

	k.K8sEventProcessed(metricLabel, resources.MetricDelete, err == nil)
	k.K8sEventReceived(apiGroup, metricLabel, resources.MetricDelete, true, true)

	return err
}

func (k *K8sWatcher) addCiliumNetworkPolicyV2(ciliumNPClient clientset.Interface, cnp *types.SlimCNP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	var rev uint64

	rules, policyImportErr := cnp.Parse()
	if policyImportErr == nil {
		policyImportErr = k8s.PreprocessRules(rules, k.K8sSvcCache)
		// Replace all rules with the same name, namespace and
		// resourceTypeCiliumNetworkPolicy
		if policyImportErr == nil {
			rev, policyImportErr = k.policyManager.PolicyAdd(rules, &policy.AddOptions{
				ReplaceWithLabels:   cnp.GetIdentityLabels(),
				Source:              source.CustomResource,
				ProcessingStartTime: initialRecvTime,
				Resource:            resourceID,
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

func (k *K8sWatcher) deleteCiliumNetworkPolicyV2(cnp *types.SlimCNP, resourceID ipcacheTypes.ResourceID) error {
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

	_, err = k.policyManager.PolicyDelete(cnp.GetIdentityLabels(), &policy.DeleteOptions{
		Source:   source.CustomResource,
		Resource: resourceID,
	})
	if err == nil {
		scopedLog.Info("Deleted CiliumNetworkPolicy")
	} else {
		scopedLog.WithError(err).Warn("Unable to delete CiliumNetworkPolicy")
	}
	return err
}

func (k *K8sWatcher) updateCiliumNetworkPolicyV2(ciliumNPClient clientset.Interface,
	oldRuleCpy, newRuleCpy *types.SlimCNP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID) error {

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

	return k.addCiliumNetworkPolicyV2(ciliumNPClient, newRuleCpy, initialRecvTime, resourceID)
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

func (k *K8sWatcher) registerResourceWithSyncFn(ctx context.Context, resource string, syncFn func() bool) {
	k.blockWaitGroupToSyncResources(ctx.Done(), nil, syncFn, resource)
	k.k8sAPIGroups.AddAPI(resource)
}

// reportCNPChangeMetrics generates metrics for changes (Add, Update, Delete) to
// Cilium Network Policies depending on the operation's success.
func reportCNPChangeMetrics(err error) {
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
	} else {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	}
}
