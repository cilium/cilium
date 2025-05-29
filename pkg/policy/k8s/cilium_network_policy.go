// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func (p *policyWatcher) onUpsert(
	cnp *types.SlimCNP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
	dc chan uint64,
) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	oldCNP, ok := p.cnpCache[key]
	if ok {
		// no generation change; this was a status update.
		if oldCNP.Generation == cnp.Generation {
			return nil
		}
		if oldCNP.DeepEqual(cnp) {
			return nil
		}

		p.log.Debug(
			"Modified CiliumNetworkPolicy",
			logfields.K8sAPIVersion, cnp.TypeMeta.APIVersion,
			logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
			logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
			logfields.AnnotationsOld, oldCNP.ObjectMeta.Annotations,
			logfields.Annotations, cnp.ObjectMeta.Annotations,
		)
	}

	if cnp.RequiresDerivative() {
		return nil
	}

	// check if this cnp was referencing or is now referencing at least one ToServices rule
	if hasToServices(cnp) {
		p.toServicesPolicies[key] = struct{}{}
	} else {
		if _, hadToServices := p.toServicesPolicies[key]; hadToServices {
			// transitioning from with toServices to without toServices
			delete(p.toServicesPolicies, key)
			// Clear ToServices index
			for svcID := range p.cnpByServiceID {
				p.clearCNPForService(key, svcID)
			}
		}
	}

	return p.resolveCiliumNetworkPolicyRefs(cnp, key, initialRecvTime, resourceID, dc)
}

func (p *policyWatcher) onDelete(
	cnp *types.SlimCNP,
	key resource.Key,
	apiGroup string,
	resourceID ipcacheTypes.ResourceID,
	dc chan uint64,
) {
	p.deleteCiliumNetworkPolicyV2(cnp, resourceID, dc)

	delete(p.cnpCache, key)

	// Clear ToServices index
	for svcID := range p.cnpByServiceID {
		p.clearCNPForService(key, svcID)
	}
	delete(p.toServicesPolicies, key)

	p.k8sResourceSynced.SetEventTimestamp(apiGroup)
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
	dc chan uint64,
) error {
	// We need to deepcopy this structure because we are writing
	// fields in cnp.Parse() in upsertCiliumNetworkPolicyV2.
	// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
	translatedCNP := cnp.DeepCopy()

	// Resolve ToService references
	if _, exists := p.toServicesPolicies[key]; exists {
		p.resolveToServices(key, translatedCNP)
	}

	err := p.upsertCiliumNetworkPolicyV2(translatedCNP, initialRecvTime, resourceID, dc)
	if err == nil {
		p.cnpCache[key] = cnp
	}

	return err
}

func (p *policyWatcher) upsertCiliumNetworkPolicyV2(cnp *types.SlimCNP, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID, dc chan uint64) error {
	scopedLog := p.log.With(
		logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion, cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
	)

	scopedLog.Debug(
		"Adding CiliumNetworkPolicy",
	)
	namespace := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)
	if namespace == "" {
		p.metricsManager.AddCCNP(cnp.CiliumNetworkPolicy)
	} else {
		p.metricsManager.AddCNP(cnp.CiliumNetworkPolicy)
	}

	rules, err := cnp.Parse(scopedLog, cmtypes.LocalClusterNameForPolicies(p.clusterMeshPolicyConfig, p.config.ClusterName))
	if err != nil {
		scopedLog.Warn(
			"Unable to add CiliumNetworkPolicy",
			logfields.Error, err,
		)
		return fmt.Errorf("failed to parse CiliumNetworkPolicy %s/%s: %w", cnp.ObjectMeta.Namespace, cnp.ObjectMeta.Name, err)
	}
	if dc != nil {
		if cnp.ObjectMeta.Namespace == "" {
			p.ccnpSyncPending.Add(1)
		} else {
			p.cnpSyncPending.Add(1)
		}
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:               rules,
		Source:              source.CustomResource,
		ProcessingStartTime: initialRecvTime,
		Resource:            resourceID,
		DoneChan:            dc,
	})
	scopedLog.Info(
		"Imported CiliumNetworkPolicy",
	)
	return nil
}

func (p *policyWatcher) deleteCiliumNetworkPolicyV2(cnp *types.SlimCNP, resourceID ipcacheTypes.ResourceID, dc chan uint64) {
	p.log.Debug("Deleting CiliumNetworkPolicy",
		logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion, cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
	)
	namespace := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)
	if namespace == "" {
		p.metricsManager.DelCCNP(cnp.CiliumNetworkPolicy)
	} else {
		p.metricsManager.DelCNP(cnp.CiliumNetworkPolicy)
	}

	if dc != nil {
		if cnp.ObjectMeta.Namespace == "" {
			p.ccnpSyncPending.Add(1)
		} else {
			p.cnpSyncPending.Add(1)
		}
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Source:   source.CustomResource,
		Resource: resourceID,
		DoneChan: dc,
	})
	p.log.Info("Deleted CiliumNetworkPolicy",
		logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion, cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
	)
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
