// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/metrics"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"clustermesh",
	"ClusterMesh is the Cilium multicluster implementation",

	cell.Provide(NewClusterMesh),

	// Convert concrete objects into more restricted interfaces used by clustermesh.
	cell.ProvidePrivate(func(sc *k8s.ServiceCache) ServiceMerger { return sc }),
	cell.ProvidePrivate(func(ipcache *ipcache.IPCache) ipcache.IPCacher { return ipcache }),
	cell.ProvidePrivate(func(mgr nodemanager.NodeManager) (nodeStore.NodeManager, kvstore.ClusterSizeDependantIntervalFunc) {
		return mgr, mgr.ClusterSizeDependantInterval
	}),
	cell.ProvidePrivate(idsMgrProvider),

	cell.Config(common.DefaultConfig),
	cell.Config(wait.TimeoutConfigDefault),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(subsystem)),

	cell.Invoke(func(info types.ClusterInfo, dcfg *option.DaemonConfig, cnimgr cni.CNIConfigManager) error {
		return info.ValidateBuggyClusterID(dcfg.IPAM, cnimgr.GetChainingMode())
	}),
	cell.Invoke(ipsetNotifier),
	cell.Invoke(nodeManagerNotifier),
)
