// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/cilium/pkg/clustermesh/internal"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"clustermesh",
	"ClusterMesh is the Cilium multicluster implementation",

	cell.Provide(NewClusterMesh),

	// Convert concrete objects into more restricted interfaces used by clustermesh.
	cell.ProvidePrivate(func(sc *k8s.ServiceCache) (ServiceMerger, k8s.ServiceIPGetter) { return sc, sc }),
	cell.ProvidePrivate(func(ipcache *ipcache.IPCache) ipcache.IPCacher { return ipcache }),
	cell.ProvidePrivate(func(mgr nodemanager.NodeManager) (store.Observer, kvstore.ClusterSizeDependantIntervalFunc) {
		return nodeStore.NewNodeObserver(mgr), mgr.ClusterSizeDependantInterval
	}),
	cell.ProvidePrivate(func() store.KeyCreator { return nodeStore.KeyCreator }),
	cell.ProvidePrivate(func(cfg *option.DaemonConfig) types.ClusterIDName {
		return types.ClusterIDName{ClusterID: cfg.ClusterID, ClusterName: cfg.ClusterName}
	}),
	cell.ProvidePrivate(idsMgrProvider),

	cell.Config(internal.Config{}),

	cell.Metric(newMetrics),
	cell.Metric(internal.MetricsProvider(subsystem)),
)
