// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"github.com/cilium/hive/cell"
)

// Cell implements the ztunnel server.
var Cell = cell.Module(
	"cilium-zds-server",
	"Workload discovery server for ztunnel",
	cell.Provide(newZDSServer),
)
