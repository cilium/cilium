// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachecell

import (
	"context"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

// registerAPIServerBackendWatcher registers a background job that watches
// backends of default/kubernetes to associate them with  the 'reserved:kube-apiserver'
// label in the IPCache. This allows policy selectors for the kube-apiserver entity to
// match these peers.
//
// The actual implementation of this logic down to the datapath is handled
// asynchronously by IPCache.
func registerAPIServerBackendWatcher(jobs job.Group, db *statedb.DB, backends statedb.Table[*loadbalancer.Backend], ipc *ipcache.IPCache) {
	jobs.Add(
		job.OneShot(
			"api-server-backend-watcher",
			func(ctx context.Context, health cell.Health) error {
				for {
					// Get all backend IPs associated to the api-server
					bes, watch := backends.ListWatch(
						db.ReadTxn(),
						loadbalancer.BackendByServiceName(loadbalancer.NewServiceName("default", "kubernetes")))

					desiredIPs := make(map[cmtypes.PrefixCluster]struct{})
					for be := range bes {
						addr := be.Address.Addr()
						desiredIPs[cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen()))] = struct{}{}
					}
					resource := ipcacheTypes.NewResourceID(
						ipcacheTypes.ResourceKindEndpoint,
						"default",
						"kubernetes",
					)

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
					ipc.RemoveLabelsExcluded(
						labels.LabelKubeAPIServer,
						desiredIPs,
						resource,
					)

					for ip := range desiredIPs {
						ipc.UpsertMetadata(ip, src, resource, labels.LabelKubeAPIServer)
					}

					select {
					case <-ctx.Done():
						return nil
					case <-watch:
					}
				}
			},
		),
	)
}
