// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"kvstore-utils",
	"Provides factory for kvstore related synchronizers",

	cell.Provide(NewFactory),

	cell.Metric(MetricsProvider),
)

type Factory interface {
	NewSyncStore(clusterName string, backend SyncStoreBackend, prefix string, opts ...WSSOpt) SyncStore
	NewWatchStore(clusterName string, keyCreator KeyCreator, observer Observer, opts ...RWSOpt) WatchStore
	NewWatchStoreManager(backend WatchStoreBackend, clusterName string) WatchStoreManager
}

type factoryImpl struct {
	metrics *Metrics
}

func (w *factoryImpl) NewSyncStore(clusterName string, backend SyncStoreBackend, prefix string, opts ...WSSOpt) SyncStore {
	return newWorkqueueSyncStore(clusterName, backend, prefix, w.metrics, opts...)
}

func (w *factoryImpl) NewWatchStore(clusterName string, keyCreator KeyCreator, observer Observer, opts ...RWSOpt) WatchStore {
	return newRestartableWatchStore(clusterName, keyCreator, observer, w.metrics, opts...)
}

func (w *factoryImpl) NewWatchStoreManager(backend WatchStoreBackend, clusterName string) WatchStoreManager {
	return newWatchStoreManagerSync(backend, clusterName, w)
}

func NewFactory(storeMetrics *Metrics) Factory {
	return &factoryImpl{
		metrics: storeMetrics,
	}
}
