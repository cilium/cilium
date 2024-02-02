// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

var Cell = cell.Module(
	"rib",
	"Routing Information Base",
	cell.Provide(
		newRIBTable,
		newFIBTable,
	),
	cell.Invoke(
		func(db *statedb.DB, rib RIB, fib FIB) {
			db.RegisterTable(rib, fib)
		},
		registerProcessor,
	),
)
