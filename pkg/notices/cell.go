// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package notices

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// Cell provides [Notices] and [statedb.Table[Notice]], an API for posting notices
// to the user about exceptional, but non-fatal circumstances in the agent.
//
// The notices are shown to the user via "cilium status"
var Cell = cell.Module(
	"notices",
	"Agent informational notices to the user",

	cell.ProvidePrivate(
		NewNoticeTable, // RWTable[Notice]
	),
	cell.Provide(
		statedb.RWTable[Notice].ToTable, // Table[Notice]
		NewNotices,
	),

	// Register a background job to post a notice when health is degraded.
	cell.Invoke(registerPostHealth),
)
