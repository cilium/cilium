// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslice

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	endpointslicetypes "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func newFactory(params params) observer.Factory {
	return func(cluster string, onSync func()) observer.Observer {
		obs := &endpointSliceObserver{
			logger:        params.Logger.With(logfields.ClusterName, cluster),
			name:          cluster,
			serviceModeV2: params.ServiceModeV2,
			onSync:        onSync,
		}

		obs.store = params.StoreFactory.NewWatchStore(
			cluster,
			endpointslicetypes.KeyCreator(
				endpointslicetypes.ClusterNameValidator(cluster),
				endpointslicetypes.NamespacedNameValidator(),
				endpointslicetypes.ClusterIDValidator(&obs.clusterID),
			),
			dummyObserver{},
			store.RWSWithOnSyncCallback(func(context.Context) { onSync() }),
			store.RWSWithEntriesMetric(params.Metrics.TotalEndpointSlices.WithLabelValues(cluster)),
		)

		return obs
	}
}

type endpointSliceObserver struct {
	logger        *slog.Logger
	name          string
	clusterID     uint32
	serviceModeV2 types.ServiceModeV2
	store         store.WatchStore
	onSync        func()
	enabled       atomic.Bool
}

func (o *endpointSliceObserver) Name() observer.Name { return Name }

func (o *endpointSliceObserver) Status() observer.Status {
	return observer.Status{
		Enabled: o.enabled.Load(),
		Synced:  o.store.Synced(),
		Entries: o.store.NumEntries(),
	}
}

func (o *endpointSliceObserver) Register(mgr store.WatchStoreManager, backend kvstore.BackendOperations, cfg types.CiliumClusterConfig) {
	o.clusterID = cfg.ID

	prefix := endpointslicetypes.EndpointSliceStorePrefix
	if cfg.Capabilities.Cached {
		prefix = kvstore.StateToCachePrefix(prefix)
	}

	if o.serviceModeV2.ShouldWatchEndpointSlices() && cfg.Capabilities.EndpointSlicesExportMode != types.EndpointSlicesExportModeServicesOnly {
		o.enabled.Store(true)
		mgr.Register(prefix, func(ctx context.Context) {
			o.store.Watch(ctx, backend, kvstore.JoinKey(prefix, o.name))
		})
		return
	}

	o.enabled.Store(false)
	if o.serviceModeV2.ShouldWatchEndpointSlices() {
		o.logger.Error("Remote cluster does not support endpoint slice resources while Cilium is configured to watch them. "+
			"Global Services and MCS-API will not take into account any backends from this cluster!",
			logfields.ClusterName, o.name)
	}

	// Drain any existing endpoint slices in case the remote cluster no longer supports them.
	o.store.Drain()
	// Mimic that endpoint slices are synced if not enabled.
	o.onSync()
}

func (o *endpointSliceObserver) Drain()  { o.store.Drain() }
func (o *endpointSliceObserver) Revoke() { o.store.Drain() }

type dummyObserver struct{}

func (dummyObserver) OnUpdate(store.Key)      {}
func (dummyObserver) OnDelete(store.NamedKey) {}
