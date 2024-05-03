// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"github.com/cilium/hive/cell"
)

// This module provides an in-memory database built on top of immutable radix trees
// As the database is based on an immutable data structure, the objects inserted into
// the database MUST NOT be mutated, but rather copied first!
//
// For example use see pkg/statedb/example.
var Cell = cell.Module(
	"statedb",
	"In-memory transactional database",

	cell.Provide(
		newHiveDB,
		newDumpHandler,
		newQueryHandler,
		NewMetrics,
	),
	// NOTE: StateDB metrics are disabled until cilium/cilium has moved to using
	// cilium/statedb. This is needed as pkg/hive now includes statedb.Cell by default
	// and we need to drop this to fix the cycle.
	//metrics.Metric(NewMetrics),
)

func newHiveDB(lc cell.Lifecycle, metrics Metrics) (*DB, error) {
	db, err := NewDB(nil, metrics)
	if err != nil {
		return nil, err
	}
	lc.Append(db)
	return db, nil
}
