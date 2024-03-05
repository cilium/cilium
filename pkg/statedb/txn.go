// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/time"
)

type txn struct {
	db             *DB
	rootReadTxn    *iradix.Txn[tableEntry]   // read transaction onto the tree of tables
	writeTxns      map[tableIndex]indexTxn   // opened per-index write transactions
	modifiedTables map[TableName]*tableEntry // table entries being modified
	smus           lock.SortableMutexes      // the (sorted) table locks
	acquiredAt     time.Time                 // the time at which the transaction acquired the locks
	tableNames     string                    // plus-separated list of table names
	packageName    string                    // name of the package that created the transaction
}

type tableIndex struct {
	table TableName
	index IndexName
}

type indexTxn struct {
	*iradix.Txn[object]
	entry indexEntry
}

func (i indexTxn) Clone() indexTxn {
	return indexTxn{i.Txn.Clone(), i.entry}
}

var zeroTxn = txn{}

// txn fulfills the ReadTxn/WriteTxn interface.
func (txn *txn) getTxn() *txn {
	return txn
}

func (txn *txn) GetRevision(name TableName) Revision {
	if table, ok := txn.modifiedTables[name]; ok {
		// This is a write transaction preparing to modify the table with a
		// new revision.
		return table.revision
	}

	// This is either a read transaction, or a write transaction to tables
	// other than this table. Look up the revision from the index.
	table, ok := txn.rootReadTxn.Get([]byte(name))
	if !ok {
		panic("BUG: Table " + name + " not found")
	}
	return table.revision
}

// indexReadTxn returns a transaction to read from the specific index.
// If the table or index is not found this returns nil & error.
func (txn *txn) indexReadTxn(name TableName, index IndexName) (indexTxn, error) {
	if txn.writeTxns != nil {
		if _, ok := txn.modifiedTables[name]; ok {
			itxn, err := txn.indexWriteTxn(name, index)
			if err == nil {
				return itxn.Clone(), nil
			}
			return indexTxn{}, err
		}
	}

	table, ok := txn.rootReadTxn.Get([]byte(name))
	if !ok {
		return indexTxn{}, fmt.Errorf("table %q not found", name)
	}
	indexEntry, ok := table.indexes.Get([]byte(index))
	if !ok {
		return indexTxn{}, fmt.Errorf("index %q not found from table %q", index, name)
	}

	return indexTxn{
		indexEntry.tree.Txn(),
		indexEntry}, nil
}

// indexWriteTxn returns a transaction to read/write to a specific index.
// The created transaction is memoized and used for subsequent reads and/or writes.
func (txn *txn) indexWriteTxn(name TableName, index IndexName) (indexTxn, error) {
	if indexTreeTxn, ok := txn.writeTxns[tableIndex{name, index}]; ok {
		return indexTreeTxn, nil
	}
	table, ok := txn.modifiedTables[name]
	if !ok {
		return indexTxn{}, fmt.Errorf("table %q not found", name)
	}
	indexEntry, ok := table.indexes.Get([]byte(index))
	if !ok {
		return indexTxn{}, fmt.Errorf("index %q not found from table %q", index, name)
	}
	itxn := indexEntry.tree.Txn()
	itxn.TrackMutate(true)
	indexWriteTxn := indexTxn{itxn, indexEntry}
	txn.writeTxns[tableIndex{name, index}] = indexWriteTxn
	return indexWriteTxn, nil
}

// mustIndexReadTxn returns a transaction to read from the specific index.
// Panics if table or index are not found.
func (txn *txn) mustIndexReadTxn(name TableName, index IndexName) indexTxn {
	indexTxn, err := txn.indexReadTxn(name, index)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

// mustIndexReadTxn returns a transaction to read or write from the specific index.
// Panics if table or index not found.
func (txn *txn) mustIndexWriteTxn(name TableName, index IndexName) indexTxn {
	indexTxn, err := txn.indexWriteTxn(name, index)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

func (txn *txn) Insert(meta TableMeta, guardRevision Revision, data any) (any, bool, error) {
	if txn.rootReadTxn == nil {
		return nil, false, ErrTransactionClosed
	}

	// Look up table and allocate a new revision.
	tableName := meta.Name()
	table, ok := txn.modifiedTables[tableName]
	if !ok {
		return nil, false, tableError(tableName, ErrTableNotLockedForWriting)
	}
	oldRevision := table.revision
	table.revision++
	revision := table.revision

	obj := object{
		revision: revision,
		data:     data,
	}

	// Update the primary index first
	idKey := meta.primary().fromObject(obj).First()
	idIndexTxn := txn.mustIndexWriteTxn(tableName, meta.primary().name)
	oldObj, oldExists := idIndexTxn.Insert(idKey, obj)

	// For CompareAndSwap() validate against the given guard revision
	if guardRevision > 0 {
		if !oldExists {
			// CompareAndSwap requires the object to exist. Revert
			// the insert.
			idIndexTxn.Delete(idKey)
			table.revision = oldRevision
			return nil, false, ErrObjectNotFound
		}
		if oldObj.revision != guardRevision {
			// Revert the change. We're assuming here that it's rarer for CompareAndSwap() to
			// fail and thus we're optimizing to have only one lookup in the common case
			// (versus doing a Get() and then Insert()).
			idIndexTxn.Insert(idKey, oldObj)
			table.revision = oldRevision
			return oldObj, true, ErrRevisionNotEqual
		}
	}

	// Update revision index
	revIndexTxn := txn.mustIndexWriteTxn(tableName, RevisionIndex)
	if oldExists {
		_, ok := revIndexTxn.Delete([]byte(index.Uint64(oldObj.revision)))
		if !ok {
			panic("BUG: Old revision index entry not found")
		}

	}
	revIndexTxn.Insert([]byte(index.Uint64(revision)), obj)

	// If it's new, possibly remove an older deleted object with the same
	// primary key from the graveyard.
	if !oldExists && txn.hasDeleteTrackers(tableName) {
		if old, existed := txn.mustIndexWriteTxn(tableName, GraveyardIndex).Delete(idKey); existed {
			txn.mustIndexWriteTxn(tableName, GraveyardRevisionIndex).Delete([]byte(index.Uint64(old.revision)))
		}
	}

	// Then update secondary indexes
	for idx, indexer := range meta.secondary() {
		indexTxn := txn.mustIndexWriteTxn(tableName, idx)
		newKeys := indexer.fromObject(obj)

		if oldExists {
			// If the object already existed it might've invalidated the
			// non-primary indexes. Compute the old key for this index and
			// if the new key is different delete the old entry.
			indexer.fromObject(oldObj).Foreach(func(oldKey index.Key) {
				if !indexer.unique {
					oldKey = encodeNonUniqueKey(idKey, oldKey)
				}
				if !newKeys.Exists(oldKey) {
					indexTxn.Delete(oldKey)
				}
			})
		}
		newKeys.Foreach(func(newKey index.Key) {
			// Non-unique secondary indexes are formed by concatenating them
			// with the primary key.
			if !indexer.unique {
				newKey = encodeNonUniqueKey(idKey, newKey)
			}
			indexTxn.Insert(newKey, obj)
		})
	}

	return oldObj.data, oldExists, nil
}

func (txn *txn) hasDeleteTrackers(name TableName) bool {
	// Table is being modified, return the entry we're mutating,
	// so we can read the latest changes.
	table, ok := txn.modifiedTables[name]
	if !ok {
		// Table is not being modified, look it up from the root.
		if t, ok := txn.rootReadTxn.Get([]byte(name)); ok {
			table = &t
		} else {
			panic(fmt.Sprintf("BUG: table %q not found", name))
		}
	}
	return table.deleteTrackers.Len() > 0
}

func (txn *txn) addDeleteTracker(meta TableMeta, trackerName string, dt deleteTracker) error {
	if txn.rootReadTxn == nil {
		return ErrTransactionClosed
	}
	table, ok := txn.modifiedTables[meta.Name()]
	if !ok {
		return tableError(meta.Name(), ErrTableNotLockedForWriting)
	}
	table.deleteTrackers, _, _ = table.deleteTrackers.Insert([]byte(trackerName), dt)
	txn.db.metrics.TableDeleteTrackerCount.With(prometheus.Labels{
		"table": meta.Name(),
	}).Inc()
	return nil

}

func (txn *txn) Delete(meta TableMeta, guardRevision Revision, data any) (any, bool, error) {
	if txn.rootReadTxn == nil {
		return nil, false, ErrTransactionClosed
	}

	// Look up table and allocate a new revision.
	tableName := meta.Name()
	table, ok := txn.modifiedTables[tableName]
	if !ok {
		return nil, false, tableError(tableName, ErrTableNotLockedForWriting)
	}
	oldRevision := table.revision
	table.revision++
	revision := table.revision

	// Delete from the primary index first to grab the object.
	// We assume that "data" has only enough defined fields to
	// compute the primary key.
	idKey := meta.primary().fromObject(object{data: data}).First()
	idIndexTree := txn.mustIndexWriteTxn(tableName, meta.primary().name)
	obj, existed := idIndexTree.Delete(idKey)
	if !existed {
		return nil, false, nil
	}

	// For CompareAndDelete() validate against guard revision and if there's a mismatch,
	// revert the change.
	if guardRevision > 0 {
		if obj.revision != guardRevision {
			idIndexTree.Insert(idKey, obj)
			table.revision = oldRevision
			return obj, true, ErrRevisionNotEqual
		}
	}

	// Update revision index.
	indexTree := txn.mustIndexWriteTxn(tableName, RevisionIndex)
	if _, ok := indexTree.Delete(index.Uint64(obj.revision)); !ok {
		panic("BUG: Object to be deleted not found from revision index")
	}

	// Then update secondary indexes.
	for idx, indexer := range meta.secondary() {
		indexer.fromObject(obj).Foreach(func(key index.Key) {
			if !indexer.unique {
				key = encodeNonUniqueKey(idKey, key)
			}
			txn.mustIndexWriteTxn(tableName, idx).Delete(key)
		})
	}

	// And finally insert the object into the graveyard.
	if txn.hasDeleteTrackers(tableName) {
		graveyardIndex := txn.mustIndexWriteTxn(tableName, GraveyardIndex)
		obj.revision = revision
		if _, existed := graveyardIndex.Insert(idKey, obj); existed {
			panic("BUG: Double deletion! Deleted object already existed in graveyard")
		}
		txn.mustIndexWriteTxn(tableName, GraveyardRevisionIndex).Insert(index.Uint64(revision), obj)
	}

	return obj.data, true, nil
}

// encodeNonUniqueKey constructs the internal key to use with non-unique indexes.
// It concatenates the secondary key with the primary key and the length of the secondary key.
// The length is stored as unsigned 16-bit big endian.
// This allows looking up from the non-unique index with the secondary key by doing a prefix
// search. The length is used to safe-guard against indexers that don't terminate the key
// properly (e.g. if secondary key is "foo", then we don't want "foobar" to match).
func encodeNonUniqueKey(primary, secondary index.Key) []byte {
	key := make([]byte, 0, len(secondary)+len(primary)+2)
	key = append(key, secondary...)
	key = append(key, primary...)
	// KeySet limits size of key to 16 bits.
	return binary.BigEndian.AppendUint16(key, uint16(len(secondary)))
}

func decodeNonUniqueKey(key []byte) (primary []byte, secondary []byte) {
	// Multi-index key is [<secondary...>, <primary...>, <secondary length>]
	if len(key) < 2 {
		return nil, nil
	}
	secondaryLength := int(binary.BigEndian.Uint16(key[len(key)-2:]))
	if len(key) < secondaryLength {
		return nil, nil
	}
	return key[secondaryLength : len(key)-2], key[:secondaryLength]
}

func (txn *txn) Abort() {
	// If writeTxns is nil, this transaction has already been committed or aborted, and
	// thus there is nothing to do. We allow this without failure to allow for defer
	// pattern:
	//
	//  txn := db.WriteTxn(...)
	//  defer txn.Abort()
	//
	//  ...
	//  if err != nil {
	//    // Transaction now aborted.
	//    return err
	//  }
	//
	//  txn.Commit()
	//
	if txn.writeTxns == nil {
		return
	}

	txn.smus.Unlock()
	txn.db.metrics.WriteTxnDuration.With(prometheus.Labels{
		"tables":  txn.tableNames,
		"package": txn.packageName,
	}).Observe(time.Since(txn.acquiredAt).Seconds())
	*txn = zeroTxn
}

func (txn *txn) Commit() {
	// We operate here under the following properties:
	//
	// - Each table that we're modifying has its SortableMutex locked and held by
	//   the caller (via WriteTxn()). Concurrent updates to other tables are
	//   allowed (but not to the root pointer), and thus there may be multiple parallel
	//   Commit()'s in progress, but each of those will only process work for tables
	//   they have locked, until root is to be updated.
	//
	// - Modifications to the root pointer (db.root) are made with the db.mu acquired,
	//   and thus changes to it are always performed sequentially. The root pointer is
	//   updated atomically, and thus readers see either an old root or a new root.
	//   Both the old root and new root are immutable after they're made available via
	//   the root pointer.
	//
	// - As the root is atomically swapped to a new immutable tree of tables of indexes,
	//   a reader can acquire an immutable snapshot of all data in the database with a
	//   simpler atomic pointer load.

	// If writeTxns is nil, this transaction has already been committed or aborted, and
	// thus there is nothing to do.
	if txn.writeTxns == nil {
		return
	}

	db := txn.db

	// Commit each individual changed index to each table.
	// We don't notify yet (CommitOnly) as the root needs to be updated
	// first as otherwise readers would wake up too early.
	for tableIndex, subTxn := range txn.writeTxns {
		table, ok := txn.modifiedTables[tableIndex.table]
		if !ok {
			panic("BUG: Table " + tableIndex.table + " in writeTxns, but not in modifiedTables")
		}
		subTxn.entry.tree = subTxn.CommitOnly()
		table.indexes, _, _ =
			table.indexes.Insert([]byte(tableIndex.index), subTxn.entry)

		// Update metrics
		db.metrics.TableGraveyardObjectCount.With(
			prometheus.Labels{"table": tableIndex.table},
		).Set(float64(table.numDeletedObjects()))
		db.metrics.TableObjectCount.With(
			prometheus.Labels{"table": tableIndex.table},
		).Set(float64(table.numObjects()))
		db.metrics.TableRevision.With(
			prometheus.Labels{"table": tableIndex.table},
		).Set(float64(table.revision))
	}

	// Acquire the lock on the root tree to sequence the updates to it. We can acquire
	// it after we've built up the new table entries above, since changes to those were
	// protected by each table lock (that we're holding here).
	db.mu.Lock()

	// Since the root may have changed since the pointer was last read in WriteTxn(),
	// load it again and modify the latest version that we now have immobilised by
	// the root lock.
	rootTxn := db.root.Load().Txn()

	// Insert the modified tables into the root tree of tables.
	for name, table := range txn.modifiedTables {
		rootTxn.Insert([]byte(name), *table)
	}

	// Commit the transaction to build the new root tree and then
	// atomically store it.
	newRoot := rootTxn.CommitOnly()
	db.root.Store(newRoot)
	db.mu.Unlock()

	// With the root pointer updated, we can now release the tables for the next write transaction.
	txn.smus.Unlock()

	// Now that new root is committed, we can notify readers by closing the watch channels of
	// mutated radix tree nodes in all changed indexes and on the root itself.
	for _, subTxn := range txn.writeTxns {
		subTxn.Notify()
	}
	rootTxn.Notify()

	// Zero out the transaction to make it inert.
	*txn = zeroTxn
}

// WriteJSON marshals out the whole database as JSON into the given writer.
func (txn *txn) WriteJSON(w io.Writer) error {
	buf := bufio.NewWriter(w)
	buf.WriteString("{\n")
	first := true
	for _, table := range txn.db.tables {
		if !first {
			buf.WriteString(",\n")
		} else {
			first = false
		}

		indexTxn := txn.getTxn().mustIndexReadTxn(table.Name(), table.primary().name)
		root := indexTxn.Root()
		iter := root.Iterator()

		buf.WriteString("  \"" + table.Name() + "\": [\n")

		_, obj, ok := iter.Next()
		for ok {
			buf.WriteString("    ")
			bs, err := json.Marshal(obj.data)
			if err != nil {
				return err
			}
			buf.Write(bs)
			_, obj, ok = iter.Next()
			if ok {
				buf.WriteString(",\n")
			} else {
				buf.WriteByte('\n')
			}
		}
		buf.WriteString("  ]")
	}
	buf.WriteString("\n}\n")
	return buf.Flush()
}
