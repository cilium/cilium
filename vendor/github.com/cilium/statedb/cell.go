// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"github.com/cilium/hive/cell"
)

// This module provides an in-memory database built on top of immutable radix trees
// As the database is based on an immutable data structure, the objects inserted into
// the database MUST NOT be mutated, but rather copied first!
var Cell = cell.Module(
	"statedb",
	"In-memory transactional database",

	cell.Provide(
		newHiveDB,
	),
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle
	Metrics   Metrics `optional:"true"`
}

func newHiveDB(p params) *DB {
	db := New(WithMetrics(p.Metrics))
	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(cell.HookContext) error {
				return db.Start()
			},
			OnStop: func(cell.HookContext) error {
				return db.Stop()
			},
		})
	return db
}
