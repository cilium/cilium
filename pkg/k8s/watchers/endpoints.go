// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net/netip"
	"sync/atomic"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func (k *K8sWatcher) endpointsInit() {
	swg := lock.NewStoppableWaitGroup()

	// Use EndpointSliceV1 API group for cache syncing regardless of the underlying
	// real resource kind since the codepath is the same for all.
	apiGroup := resources.K8sAPIGroupEndpointSliceOrEndpoint

	metric := resources.MetricEndpoint
	if k8s.SupportsEndpointSlice() {
		metric = resources.MetricEndpointSlice
	}

	var synced atomic.Bool
	synced.Store(false)

	k.blockWaitGroupToSyncResources(
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
					k.K8sEventReceived(apiGroup, metric, resources.MetricUpdate, true, false)
					k.updateEndpoint(event.Object, swg)
					k.K8sEventProcessed(metric, resources.MetricUpdate, true)
				case resource.Delete:
					k.K8sEventReceived(apiGroup, metric, resources.MetricDelete, true, false)
					k.K8sSvcCache.DeleteEndpoints(event.Object.EndpointSliceID, swg)
					k.K8sEventProcessed(metric, resources.MetricDelete, true)
				}
				event.Done(nil)
			}
		}
	}()
}

func (k *K8sWatcher) updateEndpoint(eps *k8s.Endpoints, swgEps *lock.StoppableWaitGroup) {
	k.K8sSvcCache.UpdateEndpoints(eps, swgEps)
	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateEndpoints(eps)
	}
	k.addKubeAPIServerServiceEndpoints(eps)
}

func (k *K8sWatcher) addKubeAPIServerServiceEndpoints(eps *k8s.Endpoints) {
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
	desiredIPs := make(map[netip.Prefix]struct{})
	for addrCluster := range eps.Backends {
		addr := addrCluster.Addr()
		desiredIPs[netip.PrefixFrom(addr, addr.BitLen())] = struct{}{}
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
func (k *K8sWatcher) handleKubeAPIServerServiceEPChanges(desiredIPs map[netip.Prefix]struct{}, rid ipcacheTypes.ResourceID) {
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
		k.ipcache.UpsertLabels(ip, labels.LabelKubeAPIServer, src, rid)
	}
}
