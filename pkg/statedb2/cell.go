// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// This module provides an in-memory database built on top of immutable radix trees
// As the database is based on an immutable data structure, the objects inserted into
// the database MUST NOT be mutated, but rather copied first!
//
// For example use see pkg/statedb/example.
var Cell = cell.Module(
	"statedb",
	"In-memory transactional database",

	cell.Provide(newHiveDB),
)

type tablesIn struct {
	cell.In

	TableMetas []TableMeta `group:"statedb-tables"`
}

func newHiveDB(lc hive.Lifecycle, tablesIn tablesIn) (*DB, error) {
	db, err := NewDB(tablesIn.TableMetas)
	if err != nil {
		return nil, err
	}
	lc.Append(db)
	return db, nil
}

type tableOut[Obj any] struct {
	cell.Out
	Table Table[Obj]
	Meta  TableMeta `group:"statedb-tables"`
}

// NewTableCell creates a cell for creating and registering a statedb Table[Obj].
func NewTableCell[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) cell.Cell {
	return cell.Provide(func() (tableOut[Obj], error) {
		if table, err := NewTable(tableName, primaryIndexer, secondaryIndexers...); err != nil {
			return tableOut[Obj]{}, err
		} else {
			return tableOut[Obj]{Table: table, Meta: table}, nil
		}
	})
}
