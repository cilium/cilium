// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type PolicyWatcher struct {
	log logrus.FieldLogger

	k8sResourceSynced *k8sSynced.Resources
	k8sAPIGroups      *k8sSynced.APIGroups

	policyManager PolicyManager
	K8sSvcCache   *k8s.ServiceCache

	CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_v2_alpha1.CiliumCIDRGroup]
	NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]

	// cnpCache contains both CNPs and CCNPs, stored using a common intermediate
	// representation (*types.SlimCNP). The cache is indexed on resource.Key,
	// that contains both the name and namespace of the resource, in order to
	// avoid key clashing between CNPs and CCNPs.
	// The cache contains CNPs and CCNPs in their "original form"
	// (i.e: pre-translation of each CIDRGroupRef to a CIDRSet).
	cnpCache       map[resource.Key]*types.SlimCNP
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup
	// cidrGroupPolicies is the set of policies that are referencing CiliumCIDRGroup objects.
	cidrGroupPolicies map[resource.Key]struct{}
}

func (p *PolicyWatcher) ciliumNetworkPoliciesInit(ctx context.Context) {
	var cnpSynced, ccnpSynced, cidrGroupSynced atomic.Bool
	go func() {
		cnpEvents := p.CiliumNetworkPolicies.Events(ctx)
		ccnpEvents := p.CiliumClusterwideNetworkPolicies.Events(ctx)
		cidrGroupEvents := p.CiliumCIDRGroups.Events(ctx)

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
					err = p.onUpsert(slimCNP, event.Key, k8sAPIGroupCiliumNetworkPolicyV2, resourceID)
				case resource.Delete:
					err = p.onDelete(slimCNP, event.Key, k8sAPIGroupCiliumNetworkPolicyV2, resourceID)
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
					err = p.onUpsert(slimCNP, event.Key, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, resourceID)
				case resource.Delete:
					err = p.onDelete(slimCNP, event.Key, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, resourceID)
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
					err = p.onUpsertCIDRGroup(event.Object, k8sAPIGroupCiliumCIDRGroupV2Alpha1)
				case resource.Delete:
					err = p.onDeleteCIDRGroup(event.Object.Name, k8sAPIGroupCiliumCIDRGroupV2Alpha1)
				}
				event.Done(err)
			}
			if cnpEvents == nil && ccnpEvents == nil && cidrGroupEvents == nil {
				return
			}
		}
	}()

	p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumNetworkPolicyV2, func() bool {
		return cnpSynced.Load() && cidrGroupSynced.Load()
	})
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, func() bool {
		return ccnpSynced.Load() && cidrGroupSynced.Load()
	})
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumCIDRGroupV2Alpha1, func() bool {
		return cidrGroupSynced.Load()
	})
}

func (p *PolicyWatcher) onUpsert(
	cnp *types.SlimCNP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	oldCNP, ok := p.cnpCache[key]
	if ok {
		if oldCNP.DeepEqual(cnp) {
			return nil
		}
	}

	if cnp.RequiresDerivative() {
		return nil
	}

	// check if this cnp was referencing or is now referencing at least one non-empty
	// CiliumCIDRGroup and update the relevant metric accordingly.
	cidrGroupRefs := getCIDRGroupRefs(cnp)
	cidrsSets, _ := p.cidrGroupRefsToCIDRsSets(cidrGroupRefs)
	if len(cidrsSets) > 0 {
		p.cidrGroupPolicies[key] = struct{}{}
	} else {
		delete(p.cidrGroupPolicies, key)
	}
	metrics.CIDRGroupsReferenced.Set(float64(len(p.cidrGroupPolicies)))

	// We need to deepcopy this structure because we are writing
	// fields.
	// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
	cnpCpy := cnp.DeepCopy()

	translationStart := time.Now()
	translatedCNP := p.resolveCIDRGroupRef(cnpCpy)
	metrics.CIDRGroupTranslationTimeStats.Observe(time.Since(translationStart).Seconds())

	var err error
	if ok {
		err = p.updateCiliumNetworkPolicyV2(oldCNP, translatedCNP, initialRecvTime, resourceID)
	} else {
		err = p.addCiliumNetworkPolicyV2(translatedCNP, initialRecvTime, resourceID)
	}
	if err == nil {
		p.cnpCache[key] = cnpCpy
	}

	return err
}

func (p *PolicyWatcher) onDelete(
	cnp *types.SlimCNP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
) error {
	err := p.deleteCiliumNetworkPolicyV2(cnp, resourceID)
	delete(p.cnpCache, key)

	delete(p.cidrGroupPolicies, key)
	metrics.CIDRGroupsReferenced.Set(float64(len(p.cidrGroupPolicies)))

	p.k8sResourceSynced.SetEventTimestamp(apiGroup)

	return err
}

func (p *PolicyWatcher) addCiliumNetworkPolicyV2(cnp *types.SlimCNP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID) error {
	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	rules, policyImportErr := cnp.Parse()
	if policyImportErr == nil {
		policyImportErr = k8s.PreprocessRules(rules, p.K8sSvcCache)
		// Replace all rules with the same name, namespace and
		// resourceTypeCiliumNetworkPolicy
		if policyImportErr == nil {
			_, policyImportErr = p.policyManager.PolicyAdd(rules, &policy.AddOptions{
				ReplaceWithLabels:   cnp.GetIdentityLabels(),
				Source:              source.CustomResource,
				ProcessingStartTime: initialRecvTime,
				Resource:            resourceID,
			})
		}
	}

	if policyImportErr != nil {
		scopedLog.WithError(policyImportErr).Warn("Unable to add CiliumNetworkPolicy")
	} else {
		scopedLog.Info("Imported CiliumNetworkPolicy")
	}

	return policyImportErr
}

func (p *PolicyWatcher) deleteCiliumNetworkPolicyV2(cnp *types.SlimCNP, resourceID ipcacheTypes.ResourceID) error {
	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Deleting CiliumNetworkPolicy")

	_, err := p.policyManager.PolicyDelete(cnp.GetIdentityLabels(), &policy.DeleteOptions{
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

func (p *PolicyWatcher) updateCiliumNetworkPolicyV2(
	oldRuleCpy, newRuleCpy *types.SlimCNP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID) error {

	_, err := oldRuleCpy.Parse()
	if err != nil {
		ns := oldRuleCpy.GetNamespace() // Disambiguates CNP & CCNP

		// We want to ignore parsing errors for empty policies, otherwise the
		// update to the new policy will be skipped.
		switch {
		case ns != "" && !errors.Is(err, cilium_v2.ErrEmptyCNP):
			p.log.WithError(err).WithField(logfields.Object, logfields.Repr(oldRuleCpy)).
				Warn("Error parsing old CiliumNetworkPolicy rule")
			return err
		case ns == "" && !errors.Is(err, cilium_v2.ErrEmptyCCNP):
			p.log.WithError(err).WithField(logfields.Object, logfields.Repr(oldRuleCpy)).
				Warn("Error parsing old CiliumClusterwideNetworkPolicy rule")
			return err
		}
	}

	_, err = newRuleCpy.Parse()
	if err != nil {
		p.log.WithError(err).WithField(logfields.Object, logfields.Repr(newRuleCpy)).
			Warn("Error parsing new CiliumNetworkPolicy rule")
		return err
	}

	p.log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                    oldRuleCpy.TypeMeta.APIVersion,
		logfields.CiliumNetworkPolicyName + ".old": oldRuleCpy.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":            oldRuleCpy.ObjectMeta.Namespace,
		logfields.CiliumNetworkPolicyName:          newRuleCpy.ObjectMeta.Name,
		logfields.K8sNamespace:                     newRuleCpy.ObjectMeta.Namespace,
		"annotations.old":                          oldRuleCpy.ObjectMeta.Annotations,
		"annotations":                              newRuleCpy.ObjectMeta.Annotations,
	}).Debug("Modified CiliumNetworkPolicy")

	return p.addCiliumNetworkPolicyV2(newRuleCpy, initialRecvTime, resourceID)
}

func (p *PolicyWatcher) registerResourceWithSyncFn(ctx context.Context, resource string, syncFn func() bool) {
	p.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, syncFn, resource)
	p.k8sAPIGroups.AddAPI(resource)
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
