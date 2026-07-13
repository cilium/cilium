// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
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
	scopedLog := p.log.With(
		logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion, cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
	)

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

		scopedLog.Debug(
			"Modified CiliumNetworkPolicy",
			logfields.AnnotationsOld, oldCNP.ObjectMeta.Annotations,
			logfields.Annotations, cnp.ObjectMeta.Annotations,
		)
	}

	// Do early validation for CNP object so we don't continue processing invalid objects.
	if err := cnp.Validate(); err != nil {
		scopedLog.Error("Invalid CiliumNetworkPolicy")
		return err
	}

	// Cache the valid un-sanitized CNP for use when resolving external references.
	p.cnpCache[key] = cnp

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

	p.upsertCiliumNetworkPolicyV2(cnp, key, initialRecvTime, resourceID, dc)
	return nil
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

// upsertCiliumNetworkPolicyV2 resolves all references to external resources(eg. ToServices),
// parses the rules and adds them to policy repository.
//
// NOTE: This method assumes that the provided CNP object is validated beforehand.
func (p *policyWatcher) upsertCiliumNetworkPolicyV2(
	cachedCNP *types.SlimCNP,
	key resource.Key,
	initialRecvTime time.Time,
	resourceID ipcacheTypes.ResourceID,
	dc chan uint64,
) {
	// DeepCopy the object as it will be mutated by Sanitize and later when resolving
	// external(eg. toServices) references.
	cnp := cachedCNP.DeepCopy()
	cnp.Sanitize()

	// Resolve ToService references if present.
	if _, exists := p.toServicesPolicies[key]; exists {
		p.resolveToServices(key, cnp)
	}

	scopedLog := p.log.With(
		logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion, cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
	)

	scopedLog.Debug("Adding CiliumNetworkPolicy")
	namespace := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)
	if namespace == "" {
		p.metricsManager.AddCCNP(cnp.CiliumNetworkPolicy)
	} else {
		p.metricsManager.AddCNP(cnp.CiliumNetworkPolicy)
	}

	rules := cnp.ParseRules(scopedLog, cmtypes.LocalClusterNameForPolicies(p.clusterMeshPolicyConfig, p.clusterInfo.Name))
	if dc != nil {
		if cnp.ObjectMeta.Namespace == "" {
			p.ccnpSyncPending.Add(1)
		} else {
			p.cnpSyncPending.Add(1)
		}
	}
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:               policyutils.RulesToPolicyEntries(rules),
		Source:              source.CustomResource,
		ProcessingStartTime: initialRecvTime,
		Resource:            resourceID,
		DoneChan:            dc,
	})

	scopedLog.Info("Imported CiliumNetworkPolicy")
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

// reportCNPChangeMetrics generates metrics for changes(Update, Delete) to
// Cilium Network Policies depending on the operation's success.
func reportCNPChangeMetrics(op string, err error) {
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(string(source.CustomResource), op, metrics.LabelValueOutcomeFail).Inc()
	} else {
		metrics.PolicyChangeTotal.WithLabelValues(string(source.CustomResource), op, metrics.LabelValueOutcomeSuccess).Inc()
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
