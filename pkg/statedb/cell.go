// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	memdb "github.com/hashicorp/go-memdb"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// This module provides an in-memory database built on top of immutable radix trees
// (courtesy of github.com/hashicorp/go-memdb). It adapts the go-memdb library for
// use with Hive by taking the table schemas as a group values from hive and provides
// typed API (Table[Obj]) for manipulating tables. As the database is based on an
// immutable data structure, all objects inserted into the database MUST NOT be mutated!
//
// For example use see pkg/statedb/example.
var Cell = cell.Module(
	"statedb",
	"In-memory database",

	cell.Provide(New),
)

type params struct {
	cell.In

	Lifecycle hive.Lifecycle

	// Schemas are the table schemas provided by NewTableCell/NewPrivateTableCell.
	Schemas []*memdb.TableSchema `group:"statedb-table-schemas"`
}
