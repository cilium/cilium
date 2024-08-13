// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const CiliumConfigTableName = "cilium-dynamic-config-table"

var ConfigTableIndex = statedb.Index[*ConfigEntry, string]{
	Name: "config-key",
	FromObject: func(t *ConfigEntry) index.KeySet {
		return index.NewKeySet(index.String(t.Key))
	},
	FromKey: index.String,
	Unique:  true,
}

type ConfigEntry struct {
	Key   string
	Value string
}

type ConfigTableGetter interface {
	Init()
	Get(key string) (ConfigEntry, bool)
	List() []ConfigEntry
	Watch(key string) (ConfigEntry, <-chan struct{})
}

type SimpleConfigTableGetter struct {
	db    *statedb.DB
	table statedb.RWTable[*ConfigEntry]
}

// ProvideConfigTableGetter initializes and returns a ConfigTableGetter instance using the provided database and table.
// It sets up a SimpleConfigTableGetter by supplying the StateDB and ConfigEntry table.
//
// The resulting ConfigTableGetter can be used as a dependency in a cell by including it in the cell's input parameters,
//
//	type struct {
//	  Cell.In
//	  ConfigTableGetter dynamicconfig.ConfigTableGetter
//	}
//
// Alternatively, it can be accessed through the read-only StateDB, though this is not recommended:
//
//	statedb.Table[*dynamicconfig.ConfigEntry]
func ProvideConfigTableGetter(db *statedb.DB, table statedb.RWTable[*ConfigEntry]) ConfigTableGetter {
	return SimpleConfigTableGetter{db: db, table: table}
}

// Init monitors the configuration table until it contains at least one object.
// If the table has any objects, the method exits immediately.
// The method blocks until the table is populated with at least one entry.
func (c SimpleConfigTableGetter) Init() {
	for {
		_, w := c.table.AllWatch(c.db.ReadTxn())
		if c.table.NumObjects(c.db.ReadTxn()) > 0 {
			return
		}
		<-w
	}
}

// Get retrieves a configuration entry from the configuration table based on the provided key.
// If the key is found, the method returns a ConfigEntry and boolean value of true to indicate success.
// If the key is not found, the method returns an empty ConfigEntry and false.
func (c SimpleConfigTableGetter) Get(key string) (ConfigEntry, bool) {
	obj, _, found := c.table.Get(c.db.ReadTxn(), ConfigTableIndex.Query(key))
	if !found {
		return ConfigEntry{}, false
	}
	return NewConfigEntry(obj.Key, obj.Value), true
}

// List retrieves all entries and returns them as a slice of ConfigEntry,
// or an empty slice if the table is empty.
func (c SimpleConfigTableGetter) List() []ConfigEntry {
	var entries []ConfigEntry
	iter := c.table.All(c.db.ReadTxn())
	for {
		s, _, ok := iter.Next()
		if !ok {
			break
		}
		entries = append(entries, NewConfigEntry(s.Key, s.Value))
	}
	return entries
}

// Watch returns a ConfigEntry along with a watch channel. If the entry is found,
// it returns a ConfigEntry, along with a channel that can be used to watch for
// changes to the entry. If the entry is not found, it returns an empty ConfigEntry
// and the watch channel. The watch channel is closed if the ConfigEntry changes.
func (c SimpleConfigTableGetter) Watch(key string) (ConfigEntry, <-chan struct{}) {
	obj, _, w, f := c.table.GetWatch(c.db.ReadTxn(), ConfigTableIndex.Query(key))
	if !f {
		return ConfigEntry{}, w
	}
	return NewConfigEntry(obj.Key, obj.Value), w
}

// NewConfigEntry creates and returns a new ConfigEntry instance with the specified key and value.
func NewConfigEntry(key string, value string) ConfigEntry {
	return ConfigEntry{
		Key:   key,
		Value: value,
	}
}
func NewConfigTable() (statedb.RWTable[*ConfigEntry], error) {
	return statedb.NewTable(
		CiliumConfigTableName,
		ConfigTableIndex,
	)
}

func (c Controller) upsertEntry(entries []ConfigEntry) {
	txn := c.db.WriteTxn(c.configTable)
	defer txn.Commit()

	for _, entry := range entries {
		_, _, err := c.configTable.Insert(txn, &entry)
		if err != nil {
			c.logger.Error("Upsert internal db", logfields.Key, entry.Key, logfields.Error, err)
		}
	}
}
