// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumCIDRGroupV2Alpha1          = "cilium/v2alpha1::CiliumCIDRGroup"
)

// Cell starts the K8s policy watcher. The K8s policy watcher watches all
// policy related K8s resources (Kubernetes NetworkPolicy (KNP),
// CiliumNetworkPolicy (CNP), ClusterwideCiliumNetworkPolicy (CCNP),
// and CiliumCIDRGroup (CCG)), translates them to Cilium's own
// policy representation (api.Rules) and updates the policy repository
// (via PolicyManager) accordingly.
var Cell = cell.Module(
	"policy-k8s-watcher",
	"Watches K8s policy related objects",

	cell.Invoke(startK8sPolicyWatcher),
)

type PolicyManager interface {
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
}

type serviceCache interface {
	ForEachService(func(svcID k8s.ServiceID, svc *k8s.Service, eps *k8s.Endpoints) bool)
}

type PolicyWatcherParams struct {
	cell.In

	Lifecycle cell.Lifecycle

	ClientSet client.Clientset
	Config    *option.DaemonConfig
	Logger    logrus.FieldLogger

	K8sResourceSynced *synced.Resources
	K8sAPIGroups      *synced.APIGroups

	PolicyManager promise.Promise[PolicyManager]
	ServiceCache  *k8s.ServiceCache

	CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_v2_alpha1.CiliumCIDRGroup]
	NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]
}

func startK8sPolicyWatcher(params PolicyWatcherParams) {
	if !params.ClientSet.IsEnabled() {
		return // skip watcher if K8s is not enabled
	}

	// We want to subscribe before the start hook is invoked in order to not miss
	// any events
	ctx, cancel := context.WithCancel(context.Background())
	svcCacheNotifications := serviceNotificationsQueue(ctx, params.ServiceCache.Notifications())

	p := &policyWatcher{
		log:                              params.Logger,
		config:                           params.Config,
		k8sResourceSynced:                params.K8sResourceSynced,
		k8sAPIGroups:                     params.K8sAPIGroups,
		svcCache:                         params.ServiceCache,
		svcCacheNotifications:            svcCacheNotifications,
		ciliumNetworkPolicies:            params.CiliumNetworkPolicies,
		ciliumClusterwideNetworkPolicies: params.CiliumClusterwideNetworkPolicies,
		ciliumCIDRGroups:                 params.CiliumCIDRGroups,
		networkPolicies:                  params.NetworkPolicies,

		cnpCache:          make(map[resource.Key]*types.SlimCNP),
		cidrGroupCache:    make(map[string]*cilium_v2_alpha1.CiliumCIDRGroup),
		cidrGroupPolicies: make(map[resource.Key]struct{}),

		toServicesPolicies: make(map[resource.Key]struct{}),
		cnpByServiceID:     make(map[k8s.ServiceID]map[resource.Key]struct{}),
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			policyManager, err := params.PolicyManager.Await(startCtx)
			if err != nil {
				return err
			}
			p.policyManager = policyManager
			p.watchResources(ctx)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			if cancel != nil {
				cancel()
			}
			return nil
		},
	})

	if params.Config.EnableK8sNetworkPolicy {
		p.registerResourceWithSyncFn(ctx, k8sAPIGroupNetworkingV1Core, func() bool {
			return p.knpSynced.Load()
		})
	}
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumNetworkPolicyV2, func() bool {
		return p.cnpSynced.Load() && p.cidrGroupSynced.Load()
	})
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, func() bool {
		return p.ccnpSynced.Load() && p.cidrGroupSynced.Load()
	})
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumCIDRGroupV2Alpha1, func() bool {
		return p.cidrGroupSynced.Load()
	})
}
