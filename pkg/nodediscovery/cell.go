// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import "github.com/cilium/cilium/pkg/hive/cell"

// The node discovery cell provides the local node configuration and node discovery
// which communicate changes in local node information to the API server or KVStore.
var Cell = cell.Module(
	"nodediscovery",
	"Communicate changes in local node information to the API server or KVStore",

	// Node discovery communicates changes in local node information to the API server or KVStore
	cell.Provide(NewNodeDiscovery),
	// LocalNodeConfig provides a subset of the DaemonConfig with a little pre-processing
	cell.Provide(NewLocalNodeConfig),
)
