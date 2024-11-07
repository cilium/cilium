// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
)

// The node discovery cell provides the local node configuration and node discovery
// which communicate changes in local node information to the API server or KVStore.
var Cell = cell.Module(
	"nodediscovery",
	"Communicate changes in local node information to the API server or KVStore",

	// Node discovery communicates changes in local node information to the API server or KVStore
	cell.Provide(NewNodeDiscovery),

	// Provide the function used to wait for completion of node synchronization from
	// the kvstore. This is provided as a separate type (rather than having the
	// consumer depend on the whole NodeDiscovery object) to break an import loop.
	cell.Provide(func(nd *NodeDiscovery) endpoint.KVStoreNodesWaitFn {
		return nd.WaitForKVStoreSync
	}),
)
