// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
)

// The node discovery cell provides the local node configuration and node discovery
// which communicate changes in local node information to the API server or KVStore.
var Cell = cell.Module(
	"nodediscovery",
	"Communicate changes in local node information to the API server or KVStore",

	// Node discovery communicates changes in local node information to the API server or KVStore
	cell.Provide(NewNodeDiscovery),

	// Register node discovery to the fence to ensure that we wait for node
	// synchronization from the kvstore (when enabled) before endpoint regen,
	// as nodes also contribute entries to the ipcache map, most notably about
	// the remote node IPs.
	cell.Invoke(func(nd *NodeDiscovery, fence regeneration.Fence) {
		fence.Add("kvstore-nodes", nd.WaitForKVStoreSync)
	}),
)
