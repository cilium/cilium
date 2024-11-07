// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"sort"
	"strconv"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/k8s"
)

const TableName = "cilium-configs"

var (
	keyIndex = statedb.Index[DynamicConfig, Key]{
		Name: "key",
		FromObject: func(t DynamicConfig) index.KeySet {
			return index.NewKeySet(index.Stringer(t.Key))
		},
		FromKey: index.Stringer[Key],
		Unique:  true,
	}

	ByKey = keyIndex.Query

	keyNameIndex = statedb.Index[DynamicConfig, string]{
		Name: "name",
		FromObject: func(t DynamicConfig) index.KeySet {
			return index.NewKeySet(index.String(t.Key.Name))
		},
		FromKey: index.String,
		Unique:  false,
	}
	ByName = keyNameIndex.Query
)

type Key struct {
	Name   string
	Source string
}

func (k Key) String() string {
	return k.Name + "/" + k.Source
}

type DynamicConfig struct {
	Key      Key
	Value    string
	Priority int
}

func (d DynamicConfig) TableHeader() []string {
	return []string{
		"Key",
		"Source",
		"Priority",
		"Value",
	}
}

func (d DynamicConfig) TableRow() []string {
	return []string{
		d.Key.Name,
		d.Key.Source,
		strconv.Itoa(d.Priority),
		d.Value,
	}
}

func NewConfigTable(db *statedb.DB) (statedb.RWTable[DynamicConfig], error) {
	tbl, err := statedb.NewTable(
		TableName,
		keyIndex,
		keyNameIndex,
	)
	if err != nil {
		return nil, err
	}

	return tbl, db.RegisterTable(tbl)
}

func RegisterConfigMapReflector(jobGroup job.Group, db *statedb.DB, rcs []k8s.ReflectorConfig[DynamicConfig], c Config) error {
	if !c.EnableDynamicConfig {
		return nil
	}
	for _, rc := range rcs {
		if err := k8s.RegisterReflector[DynamicConfig](jobGroup, db, rc); err != nil {
			return err
		}
	}
	return nil
}

// GetKey retrieves a DynamicConfig value accounting for the priority when the
// key is present in multiple config sources.
// It returns the DynamicConfig value associated with the key, if found and
// boolean indicating whether the key was found or not.
func GetKey(txn statedb.ReadTxn, table statedb.Table[DynamicConfig], key string) (DynamicConfig, bool) {
	entries := statedb.Collect(table.List(txn, ByName(key)))
	if len(entries) == 0 {
		return DynamicConfig{}, false
	}
	sortByPriority(entries)
	return entries[0], true
}

// WatchKey retrieves a DynamicConfig value accounting for priority when the
// key is present in multiple config sources.
// It returns the DynamicConfig value associated with the key, if found,
// a boolean indicating whether the key was found or not, and a watch channel
// that is closed if the entry is invalidated.
func WatchKey(txn statedb.ReadTxn, table statedb.Table[DynamicConfig], key string) (DynamicConfig, bool, <-chan struct{}) {
	iter, w := table.ListWatch(txn, ByName(key))
	entries := statedb.Collect(iter)
	if len(entries) == 0 {
		return DynamicConfig{}, false, w
	}
	sortByPriority(entries)
	return entries[0], true, w
}

// WatchAllKeys retrieves all DynamicConfig values accounting for priority when the
// key is present in multiple config sources.
func WatchAllKeys(txn statedb.ReadTxn, table statedb.Table[DynamicConfig]) (map[string]DynamicConfig, <-chan struct{}) {
	keyValue := map[string]DynamicConfig{}
	keyPriority := map[string]int{}

	iter, w := table.AllWatch(txn)
	for obj := range iter {
		priority, found := keyPriority[obj.Key.Name]
		if !found || priority > obj.Priority {
			keyValue[obj.Key.Name] = obj
			keyPriority[obj.Key.Name] = obj.Priority
		}
	}

	return keyValue, w
}

func sortByPriority(entries []DynamicConfig) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Priority < entries[j].Priority
	})
}
