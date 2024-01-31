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
)

type PolicyWatcher struct {
	log logrus.FieldLogger

	k8sResourceSynced *k8sSynced.Resources
	k8sAPIGroups      *k8sSynced.APIGroups

	policyManager PolicyManager
	K8sSvcCache   *k8s.ServiceCache

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
