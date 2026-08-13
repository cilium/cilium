// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import "github.com/cilium/hive/cell"

// Cell provides the REST API for querying the current cluster nodes and
// incrementally observing node changes.
var Cell = cell.Module(
	"node-rest-api",
	"Provides the REST API for querying cluster nodes",
	cell.Provide(newGetClusterNodesRESTAPIHandler),
)
