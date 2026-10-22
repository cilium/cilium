// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Cell provides the NodeManager, which manages information about Cilium nodes
// in the cluster and informs other modules of changes to node configuration.
var Cell = cell.Module(
	"node-manager",
	"Manages the collection of Cilium nodes",
	cell.Provide(newAllNodeManager),
	// Install the writer policy even when no caller injects NodeManager.
	cell.Invoke(func(NodeManager) {}),
	cell.Provide(newNodeConfigNotifier),
	metrics.Metric(NewNodeMetrics),
)

type NodeManager interface {
	// NodeUpdated is called when the store detects a change in node
	// information
	NodeUpdated(n types.Node)

	// NodeDeleted is called when the store detects a deletion of a node
	NodeDeleted(n types.Node)
}

func newAllNodeManager(in struct {
	cell.In
	Logger      *slog.Logger
	ClusterInfo cmtypes.ClusterInfo
	TunnelConf  tunnel.Config
	IPCache     *ipcache.IPCache
	NodeMetrics *nodeMetrics
	DB          *statedb.DB
	WGConfig    wgTypes.Config
	Writer      *node.Writer
},
) (NodeManager, error) {
	mngr, err := New(
		in.Logger,
		option.Config,
		in.ClusterInfo,
		in.TunnelConf,
		in.IPCache,
		in.NodeMetrics,
		in.DB,
		in.WGConfig,
		in.Writer,
	)
	if err != nil {
		return nil, err
	}
	return mngr, nil
}
