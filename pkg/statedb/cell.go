// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

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

	cell.Provide(
		newHiveDB,
		newDumpHandler,
	),
	cell.Metric(NewMetrics),
)

type tablesIn struct {
	cell.In

	TableMetas []TableMeta `group:"statedb-tables"`
	Metrics    Metrics
}

func newHiveDB(lc hive.Lifecycle, tablesIn tablesIn) (*DB, error) {
	db, err := NewDB(tablesIn.TableMetas, tablesIn.Metrics)
	if err != nil {
		return nil, err
	}
	lc.Append(db)
	return db, nil
}

type tableOut[Obj any] struct {
	cell.Out
	Reader Table[Obj]
	Writer RWTable[Obj]
	Meta   TableMeta `group:"statedb-tables"`
}

// NewTableCell creates a cell for creating and registering a statedb Table[Obj].
func NewTableCell[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) cell.Cell {
	return cell.Provide(func() (tableOut[Obj], error) {
		if writer, err := NewTable(tableName, primaryIndexer, secondaryIndexers...); err != nil {
			return tableOut[Obj]{}, err
		} else {
			return tableOut[Obj]{
				Reader: writer, // RWTable[Obj] is superset of Table[Obj]
				Writer: writer,
				Meta:   writer}, nil
		}
	})
}

type tableOutProtected[Obj any] struct {
	cell.Out
	Reader Table[Obj]
	Meta   TableMeta `group:"statedb-tables"`
}

// NewProtectedTableCell creates a cell for creating and registering a statedb Table[Obj]. The
// provided RWTable[Obj] is scoped to the module and thus prevents the table from being
// directly modified outside this module.
func NewProtectedTableCell[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) cell.Cell {
	rwtable, err := NewTable(tableName, primaryIndexer, secondaryIndexers...)
	return cell.Group(
		// Derive Table[Obj] and TableMeta from RWTable[Obj] (they're a subset of it)
		cell.Provide(func() (tableOutProtected[Obj], error) {
			if err != nil {
				return tableOutProtected[Obj]{}, err
			}
			return tableOutProtected[Obj]{Reader: rwtable, Meta: rwtable}, nil
		}),

		// Provide RWTable[Obj] only in the module's scope.
		cell.ProvidePrivate(func() (RWTable[Obj], error) {
			return rwtable, err
		}),
	)
}

type tableOutMeta[Obj any] struct {
	cell.Out
	Meta TableMeta `group:"statedb-tables"`
}

func NewPrivateRWTableCell[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) cell.Cell {
	rwtable, err := NewTable(tableName, primaryIndexer, secondaryIndexers...)
	return cell.Group(
		cell.Provide(func() (tableOutMeta[Obj], error) {
			if err != nil {
				return tableOutMeta[Obj]{}, err
			}
			return tableOutMeta[Obj]{Meta: rwtable}, nil
		}),
		// Provide RWTable[Obj] only in the module's scope.
		cell.ProvidePrivate(func() (RWTable[Obj], error) {
			return rwtable, err
		}),
	)
}
