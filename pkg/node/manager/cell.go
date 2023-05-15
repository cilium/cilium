// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"time"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the NodeManager, which manages information about Cilium nodes
// in the cluster and informs other modules of changes to node configuration.
var Cell = cell.Module(
	"node-manager",
	"Manages the collection of Cilium nodes",
	cell.Provide(newAllNodeManager),
)

// Notifier is the interface the wraps Subscribe and Unsubscribe. An
// implementation of this interface notifies subscribers of nodes being added,
// updated or deleted.
type Notifier interface {
	// Subscribe adds the given NodeHandler to the list of subscribers that are
	// notified of node changes. Upon call to this method, the NodeHandler is
	// being notified of all nodes that are already in the cluster by calling
	// the NodeHandler's NodeAdd callback.
	Subscribe(datapath.NodeHandler)

	// Unsubscribe removes the given NodeHandler from the list of subscribers.
	Unsubscribe(datapath.NodeHandler)
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

	// ClusterSizeDependantInterval returns a time.Duration that is dependent on
	// the cluster size, i.e. the number of nodes that have been discovered. This
	// can be used to control sync intervals of shared or centralized resources to
	// avoid overloading these resources as the cluster grows.
	ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration

	// StartNeighborRefresh spawns a controller which refreshes neighbor table
	// by sending arping periodically.
	StartNeighborRefresh(nh datapath.NodeNeighbors)
}

func newAllNodeManager(lc hive.Lifecycle, ipCache *ipcache.IPCache) (NodeManager, error) {
	mngr, err := New("all", option.Config, ipCache)
	if err != nil {
		return nil, err
	}
	lc.Append(mngr)
	return mngr, nil
}
