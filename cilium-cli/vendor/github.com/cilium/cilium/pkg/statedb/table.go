// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb/index"
)

// NewTable creates a new table with given name and indexes.
// Can fail if the indexes are malformed.
//
// To provide access to the table via Hive:
//
//	cell.Provide(
//		// Provide statedb.RWTable[*MyObject]. Often only provided to the module with ProvidePrivate.
//		statedb.NewTable[*MyObject]("my-objects", MyObjectIDIndex, MyObjectNameIndex),
//		// Provide the read-only statedb.Table[*MyObject].
//		statedb.RWTable[*MyObject].ToTable,
//	)
func NewTable[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) (RWTable[Obj], error) {
	toAnyIndexer := func(idx Indexer[Obj]) anyIndexer {
		return anyIndexer{
			name: idx.indexName(),
			fromObject: func(iobj object) index.KeySet {
				return idx.fromObject(iobj.data.(Obj))
			},
			unique: idx.isUnique(),
		}
	}

	table := &genTable[Obj]{
		table:                tableName,
		smu:                  lock.NewSortableMutex(),
		primaryAnyIndexer:    toAnyIndexer(primaryIndexer),
		primaryIndexer:       primaryIndexer,
		secondaryAnyIndexers: make(map[string]anyIndexer, len(secondaryIndexers)),
	}

	for _, indexer := range secondaryIndexers {
		table.secondaryAnyIndexers[indexer.indexName()] = toAnyIndexer(indexer)
	}

	// Primary index must always be unique
	if !primaryIndexer.isUnique() {
		return nil, tableError(tableName, ErrPrimaryIndexNotUnique)
	}

	// Validate that indexes have unique ids.
	indexNames := sets.New[string]()
	indexNames.Insert(primaryIndexer.indexName())
	for _, indexer := range secondaryIndexers {
		if indexNames.Has(indexer.indexName()) {
			return nil, tableError(tableName, fmt.Errorf("index %q: %w", indexer.indexName(), ErrDuplicateIndex))
		}
		indexNames.Insert(indexer.indexName())
	}
	for name := range indexNames {
		if strings.HasPrefix(name, reservedIndexPrefix) {
			return nil, tableError(tableName, fmt.Errorf("index %q: %w", name, ErrReservedPrefix))
		}
	}
	return table, nil
}

// MustNewTable creates a new table with given name and indexes.
// Panics if indexes are malformed.
func MustNewTable[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj]) RWTable[Obj] {
	t, err := NewTable[Obj](tableName, primaryIndexer, secondaryIndexers...)
	if err != nil {
		panic(err)
	}
	return t
}

type genTable[Obj any] struct {
	table                TableName
	smu                  lock.SortableMutex
	primaryIndexer       Indexer[Obj]
	primaryAnyIndexer    anyIndexer
	secondaryAnyIndexers map[string]anyIndexer
}

func (t *genTable[Obj]) tableKey() []byte {
	return []byte(t.table)
}

func (t *genTable[Obj]) PrimaryIndexer() Indexer[Obj] {
	return t.primaryIndexer
}

func (t *genTable[Obj]) primary() anyIndexer {
	return t.primaryAnyIndexer
}

func (t *genTable[Obj]) secondary() map[string]anyIndexer {
	return t.secondaryAnyIndexers
}

func (t *genTable[Obj]) Name() string {
	return t.table
}

func (t *genTable[Obj]) ToTable() Table[Obj] {
	return t
}

func (t *genTable[Obj]) Revision(txn ReadTxn) Revision {
	return txn.getTxn().GetRevision(t.table)
}

func (t *genTable[Obj]) NumObjects(txn ReadTxn) int {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.table, t.primaryAnyIndexer.name)
	return indexTxn.entry.tree.Len()
}

func (t *genTable[Obj]) First(txn ReadTxn, q Query[Obj]) (obj Obj, revision uint64, ok bool) {
	obj, revision, _, ok = t.FirstWatch(txn, q)
	return
}

func (t *genTable[Obj]) FirstWatch(txn ReadTxn, q Query[Obj]) (obj Obj, revision uint64, watch <-chan struct{}, ok bool) {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.table, q.index)
	iter := indexTxn.Root().Iterator()
	watch = iter.SeekPrefixWatch(q.key)

	var iobj object
	for {
		var key []byte
		key, iobj, ok = iter.Next()
		if !ok {
			break
		}

		// Check that we have a full match on the key
		var match bool
		if indexTxn.entry.unique {
			match = len(key) == len(q.key)
		} else {
			_, secondary := decodeNonUniqueKey(key)
			match = len(secondary) == len(q.key)
		}
		if match {
			break
		}
	}

	if ok {
		obj = iobj.data.(Obj)
		revision = iobj.revision
	}
	return
}

func (t *genTable[Obj]) Last(txn ReadTxn, q Query[Obj]) (obj Obj, revision uint64, ok bool) {
	obj, revision, _, ok = t.LastWatch(txn, q)
	return
}

func (t *genTable[Obj]) LastWatch(txn ReadTxn, q Query[Obj]) (obj Obj, revision uint64, watch <-chan struct{}, ok bool) {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.table, q.index)
	iter := indexTxn.Root().ReverseIterator()
	watch = iter.SeekPrefixWatch(q.key)

	var iobj object
	for {
		var key []byte
		key, iobj, ok = iter.Previous()
		if !ok {
			break
		}

		// Check that we have a full match on the key
		var match bool
		if indexTxn.entry.unique {
			match = len(key) == len(q.key)
		} else {
			_, secondary := decodeNonUniqueKey(key)
			match = len(secondary) == len(q.key)
		}
		if match {
			break
		}
	}

	if ok {
		obj = iobj.data.(Obj)
		revision = iobj.revision
	}
	return
}

func (t *genTable[Obj]) LowerBound(txn ReadTxn, q Query[Obj]) (Iterator[Obj], <-chan struct{}) {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.table, q.index)
	root := indexTxn.Root()

	// Since LowerBound query may be invalidated by changes in another branch
	// of the tree, we cannot just simply watch the node we seeked to. Instead
	// we watch the whole table for changes.
	watch, _, _ := root.GetWatch(nil)
	iter := root.Iterator()
	iter.SeekLowerBound(q.key)
	return &iterator[Obj]{iter}, watch
}

func (t *genTable[Obj]) All(txn ReadTxn) (Iterator[Obj], <-chan struct{}) {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.table, t.primaryAnyIndexer.name)
	root := indexTxn.Root()
	// Grab the watch channel for the root node
	watchCh, _, _ := root.GetWatch(nil)
	return &iterator[Obj]{root.Iterator()}, watchCh
}

func (t *genTable[Obj]) Get(txn ReadTxn, q Query[Obj]) (Iterator[Obj], <-chan struct{}) {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.table, q.index)
	iter := indexTxn.Root().Iterator()
	watchCh := iter.SeekPrefixWatch(q.key)

	if indexTxn.entry.unique {
		return &uniqueIterator[Obj]{iter, q.key}, watchCh
	}
	return &nonUniqueIterator[Obj]{iter, q.key}, watchCh
}

func (t *genTable[Obj]) Insert(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var data any
	data, hadOld, err = txn.getTxn().Insert(t, Revision(0), obj)
	if err == nil && hadOld {
		oldObj = data.(Obj)
	}
	return
}

func (t *genTable[Obj]) CompareAndSwap(txn WriteTxn, rev Revision, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var data any
	data, hadOld, err = txn.getTxn().Insert(t, rev, obj)
	if err == nil && hadOld {
		oldObj = data.(Obj)
	}
	return
}

func (t *genTable[Obj]) Delete(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var data any
	data, hadOld, err = txn.getTxn().Delete(t, Revision(0), obj)
	if err == nil && hadOld {
		oldObj = data.(Obj)
	}
	return
}

func (t *genTable[Obj]) CompareAndDelete(txn WriteTxn, rev Revision, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var data any
	data, hadOld, err = txn.getTxn().Delete(t, rev, obj)
	if err == nil && hadOld {
		oldObj = data.(Obj)
	}
	return
}

func (t *genTable[Obj]) DeleteAll(txn WriteTxn) error {
	iter, _ := t.All(txn)
	itxn := txn.getTxn()
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		_, _, err := itxn.Delete(t, Revision(0), obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *genTable[Obj]) DeleteTracker(txn WriteTxn, trackerName string) (*DeleteTracker[Obj], error) {
	dt := &DeleteTracker[Obj]{
		db:          txn.getTxn().db,
		trackerName: trackerName,
		table:       t,
	}
	err := txn.getTxn().addDeleteTracker(t, trackerName, dt)
	if err != nil {
		return nil, err
	}
	return dt, nil
}

func (t *genTable[Obj]) sortableMutex() lock.SortableMutex {
	return t.smu
}

var _ Table[bool] = &genTable[bool]{}
var _ RWTable[bool] = &genTable[bool]{}
