// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/metrics"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
)

var Cell = cell.Module(
	"clustermesh",
	"ClusterMesh is the Cilium multicluster implementation",

	cell.Provide(NewClusterMesh),

	// Convert concrete objects into more restricted interfaces used by clustermesh.
	cell.ProvidePrivate(func(log *slog.Logger, sc *k8s.ServiceCache, w *experimental.Writer) ServiceMerger {
		if w.IsEnabled() {
			return newExperimentalServiceMerger(log, w)
		}
		return sc
	}),
	cell.ProvidePrivate(func(ipcache *ipcache.IPCache) ipcache.IPCacher { return ipcache }),
	cell.ProvidePrivate(func(mgr nodemanager.NodeManager) (nodeStore.NodeManager, kvstore.ClusterSizeDependantIntervalFunc) {
		return mgr, mgr.ClusterSizeDependantInterval
	}),
	cell.ProvidePrivate(idsMgrProvider),

	cell.Config(common.DefaultConfig),
	cell.Config(wait.TimeoutConfigDefault),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(subsystem)),

	cell.Invoke(ipsetNotifier),
	cell.Invoke(nodeManagerNotifier),
)
