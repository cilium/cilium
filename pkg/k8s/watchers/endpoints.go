// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/source"
)

type k8sEndpointsWatcherParams struct {
	cell.In

	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	ServiceCache k8s.ServiceCache
	IPCache      *ipcache.IPCache
}

func newK8sEndpointsWatcher(params k8sEndpointsWatcherParams) *K8sEndpointsWatcher {
	return &K8sEndpointsWatcher{
		k8sResourceSynced: params.K8sResourceSynced,
		k8sAPIGroups:      params.K8sAPIGroups,
		resources:         params.Resources,
		k8sSvcCache:       params.ServiceCache,
		ipcache:           params.IPCache,
		stop:              make(chan struct{}),
	}
}

type K8sEndpointsWatcher struct {
	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources
	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups
	resources    agentK8s.Resources

	k8sSvcCache k8s.ServiceCache
	ipcache     ipcacheManager

	stop chan struct{}
}

func (k *K8sEndpointsWatcher) endpointsInit() {
	swg := lock.NewStoppableWaitGroup()

	// Use EndpointSliceV1 API group for cache syncing regardless of the underlying
	// real resource kind since the codepath is the same for all.
	apiGroup := resources.K8sAPIGroupEndpointSliceOrEndpoint

	var synced atomic.Bool

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		k.stop,
		swg,
		func() bool { return synced.Load() },
		apiGroup,
	)
	k.k8sAPIGroups.AddAPI(apiGroup)

	ctx, cancel := context.WithCancel(context.Background())
	events := k.resources.Endpoints.Events(ctx)
	go func() {
		for {
			select {
			case <-k.stop:
				cancel()
			case event, ok := <-events:
				if !ok {
					return
				}
				switch event.Kind {
				case resource.Sync:
					synced.Store(true)
				case resource.Upsert:
					k.k8sResourceSynced.SetEventTimestamp(apiGroup)
					k.updateEndpoint(event.Object, swg)
				case resource.Delete:
					k.k8sResourceSynced.SetEventTimestamp(apiGroup)
					k.k8sSvcCache.DeleteEndpoints(event.Object.EndpointSliceID, swg)
				}
				event.Done(nil)
			}
		}
	}()
}

func (k *K8sEndpointsWatcher) stopWatcher() {
	close(k.stop)
}

func (k *K8sEndpointsWatcher) updateEndpoint(eps *k8s.Endpoints, swgEps *lock.StoppableWaitGroup) {
	k.k8sSvcCache.UpdateEndpoints(eps, swgEps)
	k.addKubeAPIServerServiceEndpoints(eps)
}

func (k *K8sEndpointsWatcher) addKubeAPIServerServiceEndpoints(eps *k8s.Endpoints) {
	if eps == nil ||
		eps.EndpointSliceID.ServiceID.Name != "kubernetes" ||
		eps.EndpointSliceID.ServiceID.Namespace != "default" {
		return
	}
	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindEndpoint,
		eps.ObjectMeta.GetNamespace(),
		eps.ObjectMeta.GetName(),
	)
	desiredIPs := make(map[cmtypes.PrefixCluster]struct{})
	for addrCluster := range eps.Backends {
		addr := addrCluster.Addr()
		desiredIPs[cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen()))] = struct{}{}
	}
	k.handleKubeAPIServerServiceEPChanges(desiredIPs, resource)
}

// handleKubeAPIServerServiceEPChanges associates the set of 'desiredIPs' with
// the 'reserved:kube-apiserver' label in the IPCache. This allows policy
// selectors for the kube-apiserver entity to match these peers.
//
// Any IPs currently associated with the apiserver that are not part of
// 'desiredIPs' will be disassociated from the apiserver following a call to
// this function.
//
// The actual implementation of this logic down to the datapath is handled
// asynchronously.
func (k *K8sEndpointsWatcher) handleKubeAPIServerServiceEPChanges(desiredIPs map[cmtypes.PrefixCluster]struct{}, rid ipcacheTypes.ResourceID) {
	src := source.KubeAPIServer

	// We must perform a diff on the ipcache.identityMetadata map in order to
	// figure out which IPs are stale and should be removed, before we inject
	// new IPs into the ipcache. The reason is because kube-apiserver will
	// constantly reconcile this specific object, even when it's been deleted;
	// effectively, this means we can avoid listening for the delete event.
	// Therefore, any changes to this specific object can be handled in a
	// "flattened" manner, since the most up-to-date form of it will be an add
	// or update event. The former is sent when Cilium is syncing with K8s and
	// the latter is sent anytime after.
	//
	// For example:
	//   * if a backend is removed or updated, then this will be in the form of
	//     an update event.
	//   * if the entire object is deleted, then it will quickly be recreated
	//     and this will be in the form of an add event.
	k.ipcache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer,
		desiredIPs,
		rid,
	)

	for ip := range desiredIPs {
		k.ipcache.UpsertMetadata(ip, src, rid, labels.LabelKubeAPIServer)
	}
}
