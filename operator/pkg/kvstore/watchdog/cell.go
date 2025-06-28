// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchdog

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"kvstore-stale-locks-watchdog",
	"Collect stale distributed locks leaked by the agents",

	cell.Invoke(runWatchdog),
)
