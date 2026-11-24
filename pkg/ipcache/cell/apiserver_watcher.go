// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachecell

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
)

// registerAPIServerBackendWatcher registers a background job that watches
// backends of default/kubernetes to associate them with  the 'reserved:kube-apiserver'
// label in the IPCache. This allows policy selectors for the kube-apiserver entity to
// match these peers.
//
// The actual implementation of this logic down to the datapath is handled
// asynchronously by IPCache.
func registerAPIServerBackendWatcher(log *slog.Logger, jobs job.Group, db *statedb.DB, backends statedb.Table[*loadbalancer.Backend], ipc *ipcache.IPCache) {
	w := &watcher{
		log:              log,
		db:               db,
		backends:         backends,
		ipc:              ipc,
		existingPrefixes: set.NewSet[cmtypes.PrefixCluster](),
	}

	jobs.Add(job.OneShot(
		"api-server-backend-watcher",
		w.watchAPIServer,
	))
}

type watcher struct {
	log      *slog.Logger
	db       *statedb.DB
	backends statedb.Table[*loadbalancer.Backend]
	ipc      *ipcache.IPCache

	existingPrefixes set.Set[cmtypes.PrefixCluster]
}

// watchAPIServer watches the kubernetes apiserver service.
// It sets the special label `reserved:kube-apiserver` for all IPs
// in that service.
func (w *watcher) watchAPIServer(ctx context.Context, h cell.Health) error {
	serviceName := loadbalancer.NewServiceName("default", "kubernetes")
	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindEndpoint,
		"default",
		"kubernetes",
	)
	src := source.KubeAPIServer

	for {
		// Get all backend IPs associated to the api-server
		bes, watch := loadbalancer.ListBackendsByServiceName(
			w.db.ReadTxn(),
			w.backends,
			serviceName)

		newPrefixes := set.NewSet[cmtypes.PrefixCluster]()
		for be := range bes {
			addr := be.Address.Addr()
			newPrefixes.Insert(
				cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen())))
		}

		adds := []ipcache.MU{}
		for newPrefix := range newPrefixes.Members() {
			if !w.existingPrefixes.Has(newPrefix) {
				w.log.Info("learned new backend for default/kubernetes, setting labels",
					logfields.IPAddr, newPrefix.AsPrefix().String(),
					logfields.Labels, labels.LabelKubeAPIServer,
				)
				adds = append(adds, ipcache.MU{
					Prefix:   newPrefix,
					Source:   src,
					Resource: resource,
					Metadata: []ipcache.IPMetadata{labels.LabelKubeAPIServer},
				})
			}
		}
		if len(adds) > 0 {
			w.ipc.UpsertMetadataBatch(adds...)
		}

		dels := []ipcache.MU{}
		for oldPrefix := range w.existingPrefixes.Members() {
			if !newPrefixes.Has(oldPrefix) {
				w.log.Info("deleted backend for default/kubernetes, removing labels",
					logfields.IPAddr, oldPrefix.AsPrefix().String(),
					logfields.Labels, labels.LabelKubeAPIServer,
				)
				dels = append(dels, ipcache.MU{
					Prefix:   oldPrefix,
					Source:   src,
					Resource: resource,
					Metadata: []ipcache.IPMetadata{labels.LabelKubeAPIServer},
				})
			}
		}
		if len(dels) > 0 {
			w.ipc.RemoveMetadataBatch(dels...)
		}

		w.existingPrefixes = newPrefixes

		if w.existingPrefixes.Len() > 0 {
			h.OK("kube-apiserver backends loaded")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
	}
}
