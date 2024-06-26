// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	"github.com/sirupsen/logrus"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func (p *policyWatcher) onUpsert(
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
	var oldCidrGroupRefs []string
	if ok {
		// no generation change; this was a status update.
		if oldCNP.Generation == cnp.Generation {
			return nil
		}
		if oldCNP.DeepEqual(cnp) {
			return nil
		}

		oldCidrGroupRefs = getCIDRGroupRefs(oldCNP)

		p.log.WithFields(logrus.Fields{
			logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
			"annotations.old":                 oldCNP.ObjectMeta.Annotations,
			"annotations":                     cnp.ObjectMeta.Annotations,
		}).Debug("Modified CiliumNetworkPolicy")
	}

	if cnp.RequiresDerivative() {
		return nil
	}

	// Check if this policy is referencing any CIDR groups, and bump their
	// reference count as applicable.
	//
	// This may cause CIDRs to be inserted in to the ipcache.
	cidrGroupRefs := getCIDRGroupRefs(cnp)
	for _, ref := range cidrGroupRefs {
		if p.cidrGroupRefs.Add(ref) {
			p.applyCIDRGroup(ref)
		}
	}

	for _, ref := range oldCidrGroupRefs {
		if p.cidrGroupRefs.Delete(ref) {
			p.applyCIDRGroup(ref)
		}
	}

	// check if this cnp was referencing or is now referencing at least one ToServices rule
	if hasToServices(cnp) {
		p.toServicesPolicies[key] = struct{}{}
	} else {
		delete(p.toServicesPolicies, key)
	}

	return p.resolveCiliumNetworkPolicyRefs(cnp, key, initialRecvTime, resourceID)
}

func (p *policyWatcher) onDelete(
	cnp *types.SlimCNP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
) error {
	err := p.deleteCiliumNetworkPolicyV2(cnp, resourceID)

	oldCNP, ok := p.cnpCache[key]
	var oldCidrGroupRefs []string
	if ok {
		oldCidrGroupRefs = getCIDRGroupRefs(oldCNP)
	}

	delete(p.cnpCache, key)

	// Clear any cidrgroup reference counts
	for _, ref := range oldCidrGroupRefs {
		if p.cidrGroupRefs.Delete(ref) {
			p.applyCIDRGroup(ref)
		}
	}

	// Clear ToServices index
	for svcID := range p.cnpByServiceID {
		p.clearCNPForService(key, svcID)
	}
	delete(p.toServicesPolicies, key)

	p.k8sResourceSynced.SetEventTimestamp(apiGroup)

	return err
}

// resolveCiliumNetworkPolicyRefs resolves all the references to external resources
// (e.g. CiliumCIDRGroups) in a CNP/CCNP, inlines them into a "translated" CNP,
// and then adds the translated CNP to the policy repository.
// If the CNP was successfully imported, the raw (i.e. untranslated) CNP/CCNP
// is also added to p.cnpCache.
func (p *policyWatcher) resolveCiliumNetworkPolicyRefs(
	cnp *types.SlimCNP,
	key resource.Key,
	initialRecvTime time.Time,
	resourceID ipcacheTypes.ResourceID,
) error {
	// We need to deepcopy this structure because we are writing
	// fields in cnp.Parse() in upsertCiliumNetworkPolicyV2.
	// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
	translatedCNP := cnp.DeepCopy()

	// Resolve ToService references
	p.resolveToServices(key, translatedCNP)

	err := p.upsertCiliumNetworkPolicyV2(translatedCNP, initialRecvTime, resourceID)
	if err == nil {
		p.cnpCache[key] = cnp
	}

	return err
}

func (p *policyWatcher) upsertCiliumNetworkPolicyV2(cnp *types.SlimCNP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID) error {
	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	rules, policyImportErr := cnp.Parse()
	if policyImportErr == nil {
		_, policyImportErr = p.policyManager.PolicyAdd(rules, &policy.AddOptions{
			Source:              source.CustomResource,
			ProcessingStartTime: initialRecvTime,
			Resource:            resourceID,
			ReplaceByResource:   true,
		})
	}

	if policyImportErr != nil {
		scopedLog.WithError(policyImportErr).Warn("Unable to add CiliumNetworkPolicy")
	} else {
		scopedLog.Info("Imported CiliumNetworkPolicy")
	}

	return policyImportErr
}

func (p *policyWatcher) deleteCiliumNetworkPolicyV2(cnp *types.SlimCNP, resourceID ipcacheTypes.ResourceID) error {
	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Deleting CiliumNetworkPolicy")

	_, err := p.policyManager.PolicyDelete(nil, &policy.DeleteOptions{
		Source:           source.CustomResource,
		Resource:         resourceID,
		DeleteByResource: true,
	})
	if err == nil {
		scopedLog.Info("Deleted CiliumNetworkPolicy")
	} else {
		scopedLog.WithError(err).Warn("Unable to delete CiliumNetworkPolicy")
	}
	return err
}

func (p *policyWatcher) registerResourceWithSyncFn(ctx context.Context, resource string, syncFn func() bool) {
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

func resourceIDForCiliumNetworkPolicy(key resource.Key, cnp *types.SlimCNP) ipcacheTypes.ResourceID {
	resourceKind := ipcacheTypes.ResourceKindCNP
	if len(key.Namespace) == 0 {
		resourceKind = ipcacheTypes.ResourceKindCCNP
	}
	return ipcacheTypes.NewResourceID(
		resourceKind,
		cnp.ObjectMeta.Namespace,
		cnp.ObjectMeta.Name,
	)
}
