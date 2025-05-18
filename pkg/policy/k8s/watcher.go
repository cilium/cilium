// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/option"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

type policyWatcher struct {
	log                     *slog.Logger
	config                  *option.DaemonConfig
	clusterMeshPolicyConfig cmtypes.PolicyConfig

	k8sResourceSynced *k8sSynced.Resources
	k8sAPIGroups      *k8sSynced.APIGroups

	policyImporter        policycell.PolicyImporter
	svcCache              serviceCache
	svcCacheNotifications <-chan k8s.ServiceNotification
	ipCache               ipc

	// Number of outstanding requests still pending in the PolicyImporter
	// This is only used during initial sync; we will increment these
	// as new work is learned and decrement them as the importer makes progress.
	knpSyncPending, cnpSyncPending, ccnpSyncPending atomic.Int64

	cidrGroupSynced atomic.Bool

	ciliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	ciliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
	ciliumCIDRGroups                 resource.Resource[*cilium_v2.CiliumCIDRGroup]
	networkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]

	// cnpCache contains both CNPs and CCNPs, stored using a common intermediate
	// representation (*types.SlimCNP). The cache is indexed on resource.Key,
	// that contains both the name and namespace of the resource, in order to
	// avoid key clashing between CNPs and CCNPs.
	// The cache contains CNPs and CCNPs in their "original form"
	// (i.e: pre-translation of each CIDRGroupRef to a CIDRSet).
	cnpCache map[resource.Key]*types.SlimCNP

	cidrGroupCache map[string]*cilium_v2.CiliumCIDRGroup

	// cidrGroupCIDRs is the set of CIDRs upserted in to the ipcache
	// for a given cidrgroup
	cidrGroupCIDRs map[string]sets.Set[netip.Prefix]

	// toServicesPolicies is the set of policies that contain ToServices references
	toServicesPolicies map[resource.Key]struct{}
	cnpByServiceID     map[k8s.ServiceID]map[resource.Key]struct{}

	metricsManager CNPMetrics
}

func (p *policyWatcher) watchResources(ctx context.Context) {
	// Channels to receive results from the PolicyImporter
	// Only used during initialization
	var knpDone, cnpDone, ccnpDone chan uint64
	if p.config.EnableK8sNetworkPolicy {
		knpDone = make(chan uint64, 1024)
	}
	if p.config.EnableCiliumNetworkPolicy {
		cnpDone = make(chan uint64, 1024)
	}
	if p.config.EnableCiliumClusterwideNetworkPolicy {
		ccnpDone = make(chan uint64, 1024)
	}

	// Consume result channels, decrement outstanding work counter.
	go func() {
		knpDone := knpDone
		cnpDone := cnpDone
		ccnpDone := ccnpDone
		for {
			select {
			case <-knpDone:
				if p.knpSyncPending.Add(-1) <= 0 {
					knpDone = nil
				}
			case <-cnpDone:
				if p.cnpSyncPending.Add(-1) <= 0 {
					cnpDone = nil
				}
			case <-ccnpDone:
				if p.ccnpSyncPending.Add(-1) <= 0 {
					ccnpDone = nil
				}
			}
			if knpDone == nil && cnpDone == nil && ccnpDone == nil {
				break
			}
		}
		p.log.Info("All policy resources synchronized!")
	}()
	go func() {
		var (
			knpEvents       <-chan resource.Event[*slim_networking_v1.NetworkPolicy]
			cnpEvents       <-chan resource.Event[*cilium_v2.CiliumNetworkPolicy]
			ccnpEvents      <-chan resource.Event[*cilium_v2.CiliumClusterwideNetworkPolicy]
			cidrGroupEvents <-chan resource.Event[*cilium_v2.CiliumCIDRGroup]
			serviceEvents   <-chan k8s.ServiceNotification
		)
		// copy the done-channels so we can nil them here and stop sending, without
		// affecting the reader above
		knpDone := knpDone
		cnpDone := cnpDone
		ccnpDone := ccnpDone

		if p.config.EnableK8sNetworkPolicy {
			knpEvents = p.networkPolicies.Events(ctx)
		}
		if p.config.EnableCiliumNetworkPolicy {
			cnpEvents = p.ciliumNetworkPolicies.Events(ctx)
		}
		if p.config.EnableCiliumClusterwideNetworkPolicy {
			ccnpEvents = p.ciliumClusterwideNetworkPolicies.Events(ctx)
		}
		if p.config.EnableCiliumNetworkPolicy || p.config.EnableCiliumClusterwideNetworkPolicy {
			// Cilium CDR Group CRD is only used with CNP/CCNP.
			// https://docs.cilium.io/en/latest/network/kubernetes/ciliumcidrgroup/
			cidrGroupEvents = p.ciliumCIDRGroups.Events(ctx)
			// Service Cache Notifications are only used with CNP/CCNP.
			serviceEvents = p.svcCacheNotifications
		}

		for {
			select {
			case event, ok := <-knpEvents:
				if !ok {
					knpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					knpDone <- 0
					knpDone = nil // stop tracking pending work
					event.Done(nil)
					continue
				}

				var err error
				switch event.Kind {
				case resource.Upsert:
					err = p.addK8sNetworkPolicyV1(
						event.Object, k8sAPIGroupNetworkingV1Core, knpDone,
						cmtypes.LocalClusterNameForPolicies(p.clusterMeshPolicyConfig, p.config.ClusterName),
					)
				case resource.Delete:
					err = p.deleteK8sNetworkPolicyV1(event.Object, k8sAPIGroupNetworkingV1Core, knpDone)
				}
				event.Done(err)
			case event, ok := <-cnpEvents:
				if !ok {
					cnpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					cnpDone <- 0
					cnpDone = nil
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
					err = p.onUpsert(slimCNP, event.Key, k8sAPIGroupCiliumNetworkPolicyV2, resourceID, cnpDone)
				case resource.Delete:
					p.onDelete(slimCNP, event.Key, k8sAPIGroupCiliumNetworkPolicyV2, resourceID, cnpDone)
				}
				reportCNPChangeMetrics(err)
				event.Done(err)
			case event, ok := <-ccnpEvents:
				if !ok {
					ccnpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					ccnpDone <- 0
					ccnpDone = nil
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
					err = p.onUpsert(slimCNP, event.Key, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, resourceID, ccnpDone)
				case resource.Delete:
					p.onDelete(slimCNP, event.Key, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, resourceID, ccnpDone)
				}
				reportCNPChangeMetrics(err)
				event.Done(err)
			case event, ok := <-cidrGroupEvents:
				if !ok {
					cidrGroupEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					p.cidrGroupSynced.Store(true)
					event.Done(nil)
					continue
				}

				switch event.Kind {
				case resource.Upsert:
					p.onUpsertCIDRGroup(event.Object, k8sAPIGroupCiliumCIDRGroupV2)
				case resource.Delete:
					p.onDeleteCIDRGroup(event.Object.Name, k8sAPIGroupCiliumCIDRGroupV2)
				}
				event.Done(nil)
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
}

type CNPMetrics interface {
	AddCNP(cec *cilium_v2.CiliumNetworkPolicy)
	DelCNP(cec *cilium_v2.CiliumNetworkPolicy)
	AddCCNP(spec *cilium_v2.CiliumNetworkPolicy)
	DelCCNP(spec *cilium_v2.CiliumNetworkPolicy)
}

type cnpMetricsNoop struct {
}

func (c cnpMetricsNoop) AddCNP(cec *cilium_v2.CiliumNetworkPolicy) {
}

func (c cnpMetricsNoop) DelCNP(cec *cilium_v2.CiliumNetworkPolicy) {
}

func (c cnpMetricsNoop) AddCCNP(spec *cilium_v2.CiliumNetworkPolicy) {
}

func (c cnpMetricsNoop) DelCCNP(spec *cilium_v2.CiliumNetworkPolicy) {
}

func NewCNPMetricsNoop() CNPMetrics {
	return &cnpMetricsNoop{}
}
