// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

// Cell provides the NodeManager, which manages information about Cilium nodes
// in the cluster and informs other modules of changes to node configuration.
var Cell = cell.Module(
	"node-manager",
	"Manages the collection of Cilium nodes",
	cell.Provide(newAllNodeManager),
	cell.Provide(newNodeConfigNotifier),
	metrics.Metric(NewNodeMetrics),
)

// Notifier is the interface the wraps Subscribe and Unsubscribe. An
// implementation of this interface notifies subscribers of nodes being added,
// updated or deleted.
type Notifier interface {
	// Subscribe adds the given NodeHandler to the list of subscribers that are
	// notified of node changes. Upon call to this method, the NodeHandler is
	// being notified of all nodes that are already in the cluster by calling
	// the NodeHandler's NodeAdd callback.
	Subscribe(node.Handler)

	// Unsubscribe removes the given NodeHandler from the list of subscribers.
	Unsubscribe(node.Handler)
}

type NodeManager interface {
	Notifier

	// GetNodes returns a copy of all the nodes as a map from Identity to Node.
	GetNodes() map[types.Identity]types.Node

	// GetNodeIdentities returns a list of all node identities store in node
	// manager.
	GetNodeIdentities() []types.Identity

	// NodeUpdated is called when the store detects a change in node
	// information
	NodeUpdated(n types.Node)

	// NodeDeleted is called when the store detects a deletion of a node
	NodeDeleted(n types.Node)

	// NodeSync is called when the store completes the initial nodes listing
	NodeSync()
	// MeshNodeSync is called when the store completes the initial nodes listing including meshed nodes
	MeshNodeSync()

	// SetPrefixClusterMutatorFn allows to inject a custom prefix cluster mutator.
	// The mutator may then be applied to the PrefixCluster(s) using cmtypes.PrefixClusterFrom.
	SetPrefixClusterMutatorFn(mutator node.PrefixClusterMutatorFn)
}

func newAllNodeManager(in struct {
	cell.In
	Logger                       *slog.Logger
	Lifecycle                    cell.Lifecycle
	NodeMetrics                  *nodeMetrics
	Health                       cell.Health
	JobGroup                     job.Group
	DB                           *statedb.DB
	Devices                      statedb.Table[*tables.Device]
	Writer                       *node.Writer
	ClusterSizeDependantInterval node.ClusterSizeDependantIntervalFunc
},
) (NodeManager, error) {
	mngr, err := New(
		in.Logger,
		in.NodeMetrics,
		in.Health,
		in.JobGroup,
		in.DB,
		in.Devices,
		in.Writer,
		in.ClusterSizeDependantInterval,
	)
	if err != nil {
		return nil, err
	}
	in.Lifecycle.Append(mngr)
	return mngr, nil
}
