// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"sync/atomic"

	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	cell.ProvidePrivate(newK8sSyncRegister),
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

	K8sSyncRegister *k8sSyncRegister

	PolicyManager promise.Promise[PolicyManager]
	ServiceCache  *k8s.ServiceCache

	CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_v2_alpha1.CiliumCIDRGroup]
	NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]
}

func startK8sPolicyWatcher(p PolicyWatcherParams) {
	if !p.ClientSet.IsEnabled() {
		return // skip watcher if K8s is not enabled
	}

	// We want to subscribe before the start hook is invoked in order to not miss
	// any events
	ctx, cancel := context.WithCancel(context.Background())
	svcCacheNotifications := stream.ToChannel(ctx, p.ServiceCache.Notifications(),
		stream.WithBufferSize(int(p.Config.K8sServiceCacheSize)))

	// Registering of resources needs to happen before the lifecycle is started
	p.K8sSyncRegister.registerResources(ctx)

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			policyManager, err := p.PolicyManager.Await(startCtx)
			if err != nil {
				return err
			}

			w := &PolicyWatcher{
				log:                              p.Logger,
				config:                           p.Config,
				k8sSyncRegister:                  p.K8sSyncRegister,
				svcCache:                         p.ServiceCache,
				svcCacheNotifications:            svcCacheNotifications,
				policyManager:                    policyManager,
				CiliumNetworkPolicies:            p.CiliumNetworkPolicies,
				CiliumClusterwideNetworkPolicies: p.CiliumClusterwideNetworkPolicies,
				CiliumCIDRGroups:                 p.CiliumCIDRGroups,
				NetworkPolicies:                  p.NetworkPolicies,

				cnpCache:          make(map[resource.Key]*types.SlimCNP),
				cidrGroupCache:    make(map[string]*cilium_v2_alpha1.CiliumCIDRGroup),
				cidrGroupPolicies: make(map[resource.Key]struct{}),

				toServicesPolicies: make(map[resource.Key]struct{}),
				cnpByServiceID:     make(map[k8s.ServiceID]map[resource.Key]struct{}),
			}

			go w.watchResources(ctx)

			return nil
		},
		OnStop: func(cell.HookContext) error {
			if cancel != nil {
				cancel()
			}
			return nil
		},
	})
}

type k8sSyncRegister struct {
	k8sResourceSynced *synced.Resources
	k8sAPIGroups      *synced.APIGroups

	k8sSyncResourceFlags map[string]*atomic.Bool

	config *option.DaemonConfig
	log    logrus.FieldLogger
}

type k8sSyncRegisterParams struct {
	cell.In

	Config *option.DaemonConfig
	Logger logrus.FieldLogger

	K8sResourceSynced *synced.Resources
	K8sAPIGroups      *synced.APIGroups
}

// newK8sSyncRegister creates a new sync register where we track which K8s
// resources have been synced
func newK8sSyncRegister(p k8sSyncRegisterParams) *k8sSyncRegister {
	k8sSyncResourceFlags := map[string]*atomic.Bool{
		k8sAPIGroupCiliumNetworkPolicyV2:            new(atomic.Bool),
		k8sAPIGroupCiliumClusterwideNetworkPolicyV2: new(atomic.Bool),
		k8sAPIGroupCiliumCIDRGroupV2Alpha1:          new(atomic.Bool),
	}
	if p.Config.EnableK8sNetworkPolicy {
		k8sSyncResourceFlags[k8sAPIGroupNetworkingV1Core] = new(atomic.Bool)
	}

	return &k8sSyncRegister{
		k8sResourceSynced:    p.K8sResourceSynced,
		k8sAPIGroups:         p.K8sAPIGroups,
		k8sSyncResourceFlags: k8sSyncResourceFlags,

		config: p.Config,
		log:    p.Logger,
	}
}

// registerResources registers all resources synced by this cell. This ensures that endpoint
// regeneration does not happen before we have synced all network policies.
// For CNPs and CCNPs, we only consider them synced if both the (C)CNP and CIDRGroup
// resource has been synced. This needs to happen before the hive lifecylce is started.
func (k *k8sSyncRegister) registerResources(ctx context.Context) {
	f := k.k8sSyncResourceFlags

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, func() bool {
		return f[k8sAPIGroupCiliumNetworkPolicyV2].Load() && f[k8sAPIGroupCiliumCIDRGroupV2Alpha1].Load()
	}, k8sAPIGroupCiliumNetworkPolicyV2)

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, func() bool {
		return f[k8sAPIGroupCiliumClusterwideNetworkPolicyV2].Load() && f[k8sAPIGroupCiliumCIDRGroupV2Alpha1].Load()
	}, k8sAPIGroupCiliumClusterwideNetworkPolicyV2)

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, func() bool {
		return f[k8sAPIGroupCiliumCIDRGroupV2Alpha1].Load()
	}, k8sAPIGroupCiliumCIDRGroupV2Alpha1)

	if k.config.EnableK8sNetworkPolicy {
		k.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, func() bool {
			return f[k8sAPIGroupNetworkingV1Core].Load()
		}, k8sAPIGroupNetworkingV1Core)
	}

	// APIs handled by this cell
	for resource := range k.k8sSyncResourceFlags {
		k.k8sAPIGroups.AddAPI(resource)
	}
}

// notifySynced forwards a sync event synced.K8sResources, thereby notifying any
// subsystem waiting on a resource to be synced
func (k *k8sSyncRegister) notifySynced(resource string) {
	flag, ok := k.k8sSyncResourceFlags[resource]
	if !ok {
		k.log.WithField(logfields.Resource, resource).Error("BUG: Unregistered resource synced. Please report this bug to Cilium developers.")
		return
	}

	flag.Store(true)
}

func (k *k8sSyncRegister) setEventTimestamp(resource string) {
	k.k8sResourceSynced.SetEventTimestamp(resource)
}
