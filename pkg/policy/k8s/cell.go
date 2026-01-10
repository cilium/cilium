// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

const (
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumCIDRGroupV2                = "cilium/v2::CiliumCIDRGroup"
)

// Cell starts the K8s policy watcher. The K8s policy watcher watches all
// policy related K8s resources (Kubernetes NetworkPolicy (KNP),
// CiliumNetworkPolicy (CNP), ClusterwideCiliumNetworkPolicy (CCNP),
// and CiliumCIDRGroup (CCG)), translates them to Cilium's own
// policy representation (PolicyEntry) and updates the policy repository
// (via PolicyManager) accordingly.
var Cell = cell.Module(
	"policy-k8s-watcher",
	"Watches K8s policy related objects",

	cell.Invoke(startK8sPolicyWatcher),
)

type PolicyWatcherParams struct {
	cell.In

	Lifecycle cell.Lifecycle

	ClientSet               client.Clientset
	Config                  *option.DaemonConfig
	ClusterMeshPolicyConfig cmtypes.PolicyConfig
	Logger                  *slog.Logger

	K8sResourceSynced *synced.Resources
	K8sAPIGroups      *synced.APIGroups

	DB       *statedb.DB
	Services statedb.Table[*loadbalancer.Service]
	Backends statedb.Table[*loadbalancer.Backend]

	IPCache        policycell.IPCacher
	PolicyImporter policycell.PolicyImporter

	CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_v2.CiliumCIDRGroup]
	NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]

	MetricsManager CNPMetrics
}

func startK8sPolicyWatcher(params PolicyWatcherParams) {
	if !params.ClientSet.IsEnabled() {
		return // skip watcher if K8s is not enabled
	}

	// We want to subscribe before the start hook is invoked in order to not miss
	// any events
	ctx, cancel := context.WithCancel(context.Background())

	p := &policyWatcher{
		log:                              params.Logger,
		config:                           params.Config,
		clusterMeshPolicyConfig:          params.ClusterMeshPolicyConfig,
		policyImporter:                   params.PolicyImporter,
		k8sResourceSynced:                params.K8sResourceSynced,
		k8sAPIGroups:                     params.K8sAPIGroups,
		db:                               params.DB,
		services:                         params.Services,
		backends:                         params.Backends,
		ipCache:                          params.IPCache,
		ciliumNetworkPolicies:            params.CiliumNetworkPolicies,
		ciliumClusterwideNetworkPolicies: params.CiliumClusterwideNetworkPolicies,
		ciliumCIDRGroups:                 params.CiliumCIDRGroups,
		networkPolicies:                  params.NetworkPolicies,

		cnpCache:       make(map[resource.Key]*types.SlimCNP),
		cidrGroupCache: make(map[string]*cilium_v2.CiliumCIDRGroup),
		cidrGroupCIDRs: make(map[string]sets.Set[netip.Prefix]),

		toServicesPolicies: make(map[resource.Key]struct{}),
		cnpByServiceID:     make(map[loadbalancer.ServiceName]map[resource.Key]struct{}),
		metricsManager:     params.MetricsManager,
	}

	// Service notifications are not used if CNPs/CCNPs are disabled.
	if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
		p.serviceEvents = serviceEventStream(params.DB, params.Services, params.Backends)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
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
		p.knpSyncPending.Store(1)
		p.registerResourceWithSyncFn(ctx, k8sAPIGroupNetworkingV1Core, func() bool {
			return p.knpSyncPending.Load() == 0
		})
	}
	if params.Config.EnableCiliumNetworkPolicy {
		p.cnpSyncPending.Store(1)
		p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumNetworkPolicyV2, func() bool {
			return p.cnpSyncPending.Load() == 0 && p.cidrGroupSynced.Load()
		})
	}

	if params.Config.EnableCiliumClusterwideNetworkPolicy {
		p.ccnpSyncPending.Store(1)
		p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, func() bool {
			return p.ccnpSyncPending.Load() == 0 && p.cidrGroupSynced.Load()
		})
	}

	if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
		p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumCIDRGroupV2, func() bool {
			return p.cidrGroupSynced.Load()
		})
	}
}
