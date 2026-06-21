// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type paramsObserver struct {
	cell.In

	Logger       *slog.Logger
	StoreFactory store.Factory
	Metrics      Metrics
	CfgMCSAPI    mcsapitypes.MCSAPIConfig
	Cache        *globalServiceExportCache
	Source       *remoteClusterServiceExportSource
}

func newFactory(params paramsObserver) observer.Factory {
	return func(cluster string, onSync func()) observer.Observer {
		obs := &serviceExportObserver{
			logger:       params.Logger.With(logfields.ClusterName, cluster),
			cluster:      cluster,
			onSync:       onSync,
			enableMCSAPI: params.CfgMCSAPI.EnableMCSAPI,
		}
		obs.store = params.StoreFactory.NewWatchStore(
			cluster,
			mcsapitypes.KeyCreator(
				mcsapitypes.ClusterNameValidator(cluster),
				mcsapitypes.NamespacedNameValidator(),
			),
			&store.FuncObserver[*mcsapitypes.ValidatingMCSAPIServiceSpec]{
				OnUpdateFunc: func(obj *mcsapitypes.ValidatingMCSAPIServiceSpec) {
					params.Cache.OnUpdate(&obj.MCSAPIServiceSpec)
					params.Source.onClusterServiceExportEvent(&obj.MCSAPIServiceSpec)
				},
				OnDeleteFunc: func(obj *mcsapitypes.ValidatingMCSAPIServiceSpec) {
					params.Cache.OnDelete(&obj.MCSAPIServiceSpec)
					params.Source.onClusterServiceExportEvent(&obj.MCSAPIServiceSpec)
				},
			},
			store.RWSWithOnSyncCallback(func(context.Context) { onSync() }),
			store.RWSWithEntriesMetric(params.Metrics.TotalServiceExports.WithLabelValues(cluster)),
		)

		return obs
	}
}

type serviceExportObserver struct {
	logger  *slog.Logger
	cluster string
	store   store.WatchStore
	onSync  func()
	enabled atomic.Bool

	enableMCSAPI bool
}

func (o *serviceExportObserver) Name() observer.Name { return mcsapitypes.Name }

func (o *serviceExportObserver) Status() observer.Status {
	return observer.Status{
		Enabled: o.enabled.Load(),
		Synced:  o.store.Synced(),
		Entries: o.store.NumEntries(),
	}
}

func (o *serviceExportObserver) Register(mgr store.WatchStoreManager, backend kvstore.BackendOperations, cfg types.CiliumClusterConfig) {
	prefix := mcsapitypes.ServiceExportStorePrefix
	if cfg.Capabilities.Cached {
		prefix = kvstore.StateToCachePrefix(prefix)
	}

	if o.enableMCSAPI && cfg.Capabilities.ServiceExportsEnabled != nil {
		o.enabled.Store(true)
		mgr.Register(prefix, func(ctx context.Context) {
			o.store.Watch(ctx, backend, kvstore.JoinKey(prefix, o.cluster))
		})
		return
	}

	o.enabled.Store(false)
	if o.enableMCSAPI {
		o.logger.Warn("Remote cluster does not support MCS-API service export resources")
	}

	// Drain any existing service exports in case the remote cluster no longer supports them.
	o.store.Drain()
	// Mimic that service exports are synced if not enabled.
	o.onSync()
}

func (o *serviceExportObserver) Drain()  { o.store.Drain() }
func (o *serviceExportObserver) Revoke() { o.store.Drain() }
