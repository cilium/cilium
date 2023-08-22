// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

var Cell = cell.Module(
	"datapath-tables",
	"Datapath state tables",

	statedb.NewTableCell[*Device](deviceTableSchema),
	statedb.NewTableCell[*Route](routeTableSchema),

	L2AnnounceTableCell,
)
