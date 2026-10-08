// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"k8s.io/client-go/tools/cache"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
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
	Cache        *operator.CacheStore[*mcsapitypes.MCSAPIServiceSpec]
	Source       *operator.RemoteObjectSource[*mcsapitypes.MCSAPIServiceSpec]
}

func newGlobalServiceExportCache() *operator.CacheStore[*mcsapitypes.MCSAPIServiceSpec] {
	return operator.NewCacheStore[*mcsapitypes.MCSAPIServiceSpec](
		cache.Indexers{
			serviceExportIndex: func(obj any) ([]string, error) {
				svcExport, ok := obj.(*mcsapitypes.MCSAPIServiceSpec)
				if !ok {
					return nil, fmt.Errorf("unexpected object type: %T", obj)
				}
				return []string{svcExport.NamespacedName().String()}, nil
			},
			cache.NamespaceIndex: func(obj any) ([]string, error) {
				svcExport, ok := obj.(*mcsapitypes.MCSAPIServiceSpec)
				if !ok {
					return nil, fmt.Errorf("unexpected object type: %T", obj)
				}
				return []string{svcExport.Namespace}, nil
			},
		},
	)
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
					params.Cache.Update(&obj.MCSAPIServiceSpec)
					params.Source.OnEvent(&obj.MCSAPIServiceSpec)
				},
				OnDeleteFunc: func(obj *mcsapitypes.ValidatingMCSAPIServiceSpec) {
					params.Cache.Delete(&obj.MCSAPIServiceSpec)
					params.Source.OnEvent(&obj.MCSAPIServiceSpec)
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
