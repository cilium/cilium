// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/option"
)

type PolicyWatcher struct {
	log    logrus.FieldLogger
	config *option.DaemonConfig

	k8sResourceSynced *k8sSynced.Resources
	k8sAPIGroups      *k8sSynced.APIGroups

	policyManager         PolicyManager
	svcCache              serviceCache
	svcCacheNotifications <-chan k8s.ServiceNotification

	CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup]
	NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]

	// cnpCache contains both CNPs and CCNPs, stored using a common intermediate
	// representation (*types.SlimCNP). The cache is indexed on resource.Key,
	// that contains both the name and namespace of the resource, in order to
	// avoid key clashing between CNPs and CCNPs.
	// The cache contains CNPs and CCNPs in their "original form"
	// (i.e: pre-translation of each CIDRGroupRef to a CIDRSet).
	cnpCache       map[resource.Key]*types.SlimCNP
	cidrGroupCache map[string]*cilium_api_v2alpha1.CiliumCIDRGroup
	// cidrGroupPolicies is the set of policies that are referencing CiliumCIDRGroup objects.
	cidrGroupPolicies map[resource.Key]struct{}
	// cidrGroupPolicies is the set of policies that contain ToServices references
	toServicesPolicies map[resource.Key]struct{}
	cnpByServiceID     map[k8s.ServiceID]map[resource.Key]struct{}
}

func (p *PolicyWatcher) watchResources(ctx context.Context) {
	var knpSynced, cnpSynced, ccnpSynced, cidrGroupSynced atomic.Bool
	go func() {
		var knpEvents <-chan resource.Event[*slim_networking_v1.NetworkPolicy]
		if p.config.EnableK8sNetworkPolicy {
			knpEvents = p.NetworkPolicies.Events(ctx)
		}
		cnpEvents := p.CiliumNetworkPolicies.Events(ctx)
		ccnpEvents := p.CiliumClusterwideNetworkPolicies.Events(ctx)
		cidrGroupEvents := p.CiliumCIDRGroups.Events(ctx)
		serviceEvents := p.svcCacheNotifications

		for {
			select {
			case event, ok := <-knpEvents:
				if !ok {
					knpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					knpSynced.Store(true)
					event.Done(nil)
					continue
				}

				var err error
				switch event.Kind {
				case resource.Upsert:
					err = p.addK8sNetworkPolicyV1(event.Object, k8sAPIGroupNetworkingV1Core)
				case resource.Delete:
					err = p.deleteK8sNetworkPolicyV1(event.Object, k8sAPIGroupNetworkingV1Core)
				}
				event.Done(err)
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
			case event, ok := <-serviceEvents:
				if !ok {
					serviceEvents = nil
					break
				}

				switch event.Action {
				case k8s.UpdateService, k8s.DeleteService:
					p.onServiceEvent(event)
				}
			}
			if knpEvents == nil && cnpEvents == nil && ccnpEvents == nil && cidrGroupEvents == nil && serviceEvents == nil {
				return
			}
		}
	}()

	if p.config.EnableK8sNetworkPolicy {
		p.registerResourceWithSyncFn(ctx, k8sAPIGroupNetworkingV1Core, func() bool {
			return knpSynced.Load()
		})
	}
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
