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
		ScriptCommands,
	),
)

// CommitHookOut registers a [CommitHook].
type CommitHookOut struct {
	cell.Out

	CommitHook CommitHook `group:"statedb-commit-hooks"`
}

type params struct {
	cell.In

	Lifecycle   cell.Lifecycle
	Metrics     Metrics      `optional:"true"`
	CommitHooks []CommitHook `group:"statedb-commit-hooks"`
}

func newHiveDB(p params) *DB {
	db := New(WithMetrics(p.Metrics), WithCommitHooks(p.CommitHooks...))
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
