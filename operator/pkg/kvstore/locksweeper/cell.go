// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package locksweeper

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"kvstore-stale-locks-sweeper",
	"Collect stale distributed locks leaked by the agents",

	cell.Invoke(runLockSweeper),
)
