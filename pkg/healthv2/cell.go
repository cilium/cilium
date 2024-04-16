// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthv2

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/healthv2/types"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var Cell = cell.Module(
	"healthv2",
	"Modular Health Provider V2",
	cell.ProvidePrivate(newTablesPrivate),
	cell.Provide(
		newHealthV2Provider,
		statedb.RWTable[types.Status].ToTable,
	),
)

var (
	PrimaryIndex = statedb.Index[types.Status, types.HealthID]{
		Name: "identifier",
		FromObject: func(s types.Status) index.KeySet {
			return index.NewKeySet([]byte(s.ID.String()))
		},
		FromKey: func(k types.HealthID) index.Key {
			return index.Key([]byte(k))
		},
		Unique: true,
	}
	LevelIndex = statedb.Index[types.Status, types.Level]{
		Name: "level",
		FromObject: func(s types.Status) index.KeySet {
			return index.NewKeySet([]byte(s.Level))
		},
		FromKey: func(key types.Level) index.Key {
			return index.Key([]byte(key))
		},
		Unique: false,
	}
)

func newTablesPrivate(db *statedb.DB) (statedb.RWTable[types.Status], error) {
	statusTable, err := statedb.NewTable(HealthTableName,
		PrimaryIndex,
		LevelIndex)
	if err != nil {
		return nil, err
	}
	if err := db.RegisterTable(statusTable); err != nil {
		return nil, err
	}
	return statusTable, nil
}
