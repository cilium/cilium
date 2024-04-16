// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
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
)

const (
	k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
	k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
	k8sAPIGroupCiliumCIDRGroupV2Alpha1          = "cilium/v2alpha1::CiliumCIDRGroup"
)

// Cell provides the K8s policy watcher. The K8s policy watcher watches all
// policy related K8s resources (Kubernetes NetworkPolicy (KNP),
// CiliumNetworkPolicy (CNP), ClusterwideCiliumNetworkPolicy (CCNP),
// and CiliumCIDRGroup (CCG)), translates them to Cilium's own
// policy representation (api.Rules) and updates the policy repository
// (via PolicyManager) accordingly.
var Cell = cell.Module(
	"policy-k8s-watcher",
	"Watches K8s policy related objects",

	cell.Provide(newPolicyResourcesWatcher),
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

	ServiceCache *k8s.ServiceCache

	CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_v2_alpha1.CiliumCIDRGroup]
	NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]
}

type PolicyResourcesWatcher struct {
	params PolicyWatcherParams
}

func newPolicyResourcesWatcher(p PolicyWatcherParams) *PolicyResourcesWatcher {
	if !p.ClientSet.IsEnabled() {
		return nil // skip watcher if K8s is not enabled
	}

	return &PolicyResourcesWatcher{
		params: p,
	}
}

// WatchK8sPolicyResources starts watching Kubernetes policy resources.
// Needs to be called before K8sWatcher.InitK8sSubsystem.
func (p *PolicyResourcesWatcher) WatchK8sPolicyResources(ctx context.Context, policyManager PolicyManager) {
	w := newPolicyWatcher(ctx, policyManager, p)
	w.watchResources(ctx)
}

// newPolicyWatcher constructs a new policy watcher. Needs to be constructed
// before K8sWatcher.InitK8sSubsystem is executed.
// This constructor unfortunately cannot be started via the Hive lifecycle as
// there exists a circular dependency between this watcher and the Daemon:
// The constructor newDaemon cannot complete before all pre-existing
// K8s policy resources have been added via the PolicyManager
// (i.e. watchResources has observed the Sync event for CNP/CCNP/KNP).
// Because the PolicyManager interface itself is implemented by the Daemon
// struct, we have a circular dependency.
func newPolicyWatcher(ctx context.Context, policyManager PolicyManager, p *PolicyResourcesWatcher) *policyWatcher {
	// In order to not miss any service events, we register a subscriber here,
	// before the call to K8sWatcher.InitK8sSubsystem.
	svcCacheNotifications := stream.ToChannel(ctx, p.params.ServiceCache.Notifications(),
		stream.WithBufferSize(int(p.params.Config.K8sServiceCacheSize)))

	w := &policyWatcher{
		log:                              p.params.Logger,
		config:                           p.params.Config,
		k8sResourceSynced:                p.params.K8sResourceSynced,
		k8sAPIGroups:                     p.params.K8sAPIGroups,
		svcCache:                         p.params.ServiceCache,
		svcCacheNotifications:            svcCacheNotifications,
		policyManager:                    policyManager,
		ciliumNetworkPolicies:            p.params.CiliumNetworkPolicies,
		ciliumClusterwideNetworkPolicies: p.params.CiliumClusterwideNetworkPolicies,
		ciliumCIDRGroups:                 p.params.CiliumCIDRGroups,
		networkPolicies:                  p.params.NetworkPolicies,

		cnpCache:          make(map[resource.Key]*types.SlimCNP),
		cidrGroupCache:    make(map[string]*cilium_v2_alpha1.CiliumCIDRGroup),
		cidrGroupPolicies: make(map[resource.Key]struct{}),

		toServicesPolicies: make(map[resource.Key]struct{}),
		cnpByServiceID:     make(map[k8s.ServiceID]map[resource.Key]struct{}),
	}
	return w
}
