// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync/atomic"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
)

func (k *K8sWatcher) ciliumClusterwideNetworkPoliciesInit(ctx context.Context, cs client.Clientset) {
	var hasSynced atomic.Bool
	apiGroup := k8sAPIGroupCiliumClusterwideNetworkPolicyV2
	metricLabel := resources.MetricCCNP
	go func() {
		cache := make(map[resource.Key]*types.SlimCNP)

		for event := range k.sharedResources.CiliumClusterwideNetworkPolicies.Events(ctx) {
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
			event.Done(err)
		}
	}()

	k.blockWaitGroupToSyncResources(ctx.Done(), nil, hasSynced.Load, apiGroup)
	k.k8sAPIGroups.AddAPI(apiGroup)
}
