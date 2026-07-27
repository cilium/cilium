// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"kvstore-utils",
	"Provides factory for kvstore related synchronizers",

	cell.Provide(NewFactory),

	metrics.Metric(MetricsProvider),
)

type Factory interface {
	NewSyncStore(clusterName string, backend SyncStoreBackend, prefix string, opts ...WSSOpt) SyncStore
	NewWatchStore(clusterName string, keyCreator KeyCreator, observer Observer, opts ...RWSOpt) WatchStore
	NewWatchStoreManager(backend WatchStoreBackend, clusterName string) WatchStoreManager
}

type factoryImpl struct {
	logger  *slog.Logger
	metrics *Metrics
}

func (w *factoryImpl) NewSyncStore(clusterName string, backend SyncStoreBackend, prefix string, opts ...WSSOpt) SyncStore {
	return newWorkqueueSyncStore(w.logger, clusterName, backend, prefix, w.metrics, opts...)
}

func (w *factoryImpl) NewWatchStore(clusterName string, keyCreator KeyCreator, observer Observer, opts ...RWSOpt) WatchStore {
	return newRestartableWatchStore(w.logger, clusterName, keyCreator, observer, w.metrics, opts...)
}

func (w *factoryImpl) NewWatchStoreManager(backend WatchStoreBackend, clusterName string) WatchStoreManager {
	return newWatchStoreManagerSync(w.logger, backend, clusterName, w)
}

func NewFactory(logger *slog.Logger, storeMetrics *Metrics) Factory {
	return &factoryImpl{
		logger:  logger,
		metrics: storeMetrics,
	}
}
