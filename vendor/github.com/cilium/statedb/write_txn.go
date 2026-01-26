// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/internal"
)

// writeTxnHandle wraps the state. We need a separate heap allocated object wrapping
// the [writeTxnState] in order to be able to Abort() a committed transaction and still
// be able to reuse the state for later transactions by returning it to the pool.
type writeTxnHandle struct {
	*writeTxnState

	readTxn readTxn
}

type writeTxnState struct {
	db *DB

	handle     string
	acquiredAt time.Time     // the time at which the transaction acquired the locks
	duration   atomic.Uint64 // the transaction duration after it finished

	tableEntries []*tableEntry            // table entries being modified
	numTxns      int                      // number of index transactions opened
	smus         internal.SortableMutexes // the (sorted) table locks
	tableNames   []string

	revKey [8]byte // reusable array for storing the serialized revision key when deleting
}

func (txn *writeTxnState) unwrap() *writeTxnState {
	return txn
}

func (txn *writeTxnState) root() dbRoot {
	return txn.tableEntries
}

// txnFinalizer is called when the GC frees *txn. It checks that a WriteTxn
// has been Aborted or Committed. This is a safeguard against forgetting to
// Abort/Commit which would cause the table to be locked forever.
func txnFinalizer(handle *writeTxnHandle) {
	if handle.writeTxnState != nil {
		txn := handle.writeTxnState
		panic(fmt.Sprintf("WriteTxn from handle %s against tables %v was never Abort()'d or Commit()'d", txn.handle, txn.tableNames))
	}
}

func (txn *writeTxnState) getTableEntry(meta TableMeta) *tableEntry {
	return txn.tableEntries[meta.tablePos()]
}

// indexReadTxn returns a transaction to read from the specific index.
// If the table or index is not found this returns nil & error.
func (txn *writeTxnState) indexReadTxn(meta TableMeta, indexPos int) (tableIndexReader, error) {
	if meta.tablePos() < 0 {
		return nil, tableError(meta.Name(), ErrTableNotRegistered)
	}
	return txn.tableEntries[meta.tablePos()].indexes[indexPos], nil
}

// indexWriteTxn returns a transaction to read/write to a specific index.
// The created transaction is memoized and used for subsequent reads and/or writes.
func (txn *writeTxnState) indexWriteTxn(meta TableMeta, indexPos int) (tableIndexTxn, error) {
	table := txn.tableEntries[meta.tablePos()]
	if !table.locked {
		return nil, tableError(meta.Name(), ErrTableNotLockedForWriting)
	}
	indexEntry := table.indexes[indexPos]
	itxn, created := indexEntry.txn()
	if created {
		table.indexes[indexPos] = itxn
		txn.numTxns++
	}
	return itxn, nil
}

// mustIndexReadTxn returns a transaction to read from the specific index.
// Panics if table or index are not found.
func (txn *writeTxnState) mustIndexReadTxn(meta TableMeta, indexPos int) tableIndexReader {
	indexTxn, err := txn.indexReadTxn(meta, indexPos)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

// mustIndexReadTxn returns a transaction to read or write from the specific index.
// Panics if table or index not found.
func (txn *writeTxnState) mustIndexWriteTxn(meta TableMeta, indexPos int) tableIndexTxn {
	indexTxn, err := txn.indexWriteTxn(meta, indexPos)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

func (txn *writeTxnState) insert(meta TableMeta, guardRevision Revision, data any) (object, bool, <-chan struct{}, error) {
	return txn.modify(meta, guardRevision, data, nil)
}

func (txn *writeTxnState) modify(meta TableMeta, guardRevision Revision, newData any, merge func(old, new object) object) (object, bool, <-chan struct{}, error) {
	if txn == nil {
		return object{}, false, nil, ErrTransactionClosed
	}

	// Look up table and allocate a new revision.
	tableName := meta.Name()
	table := txn.tableEntries[meta.tablePos()]
	if !table.locked {
		return object{}, false, nil, tableError(tableName, ErrTableNotLockedForWriting)
	}
	oldRevision := table.revision
	table.revision++
	revision := table.revision

	// Update the primary index first
	obj := object{data: newData, revision: revision}
	idIndexTxn := txn.mustIndexWriteTxn(meta, PrimaryIndexPos)
	idKey := idIndexTxn.objectToKey(obj)

	var (
		oldObj    object
		oldExists bool
		watch     <-chan struct{}
	)
	if merge == nil {
		oldObj, oldExists, watch = idIndexTxn.insert(idKey, obj)
	} else {
		oldObj, oldExists, watch = idIndexTxn.modify(idKey, obj, merge)
	}

	// Sanity check: is the same object being inserted back and thus the
	// immutable object is being mutated?
	if oldExists {
		val := reflect.ValueOf(obj.data)
		if val.Kind() == reflect.Pointer {
			oldVal := reflect.ValueOf(oldObj.data)
			if val.UnsafePointer() == oldVal.UnsafePointer() {
				panic(fmt.Sprintf(
					"Insert() of the same object (%T) back into the table. Is the immutable object being mutated?",
					obj.data))
			}
		}
	}

	// For CompareAndSwap() validate against the given guard revision
	if guardRevision > 0 {
		if !oldExists {
			// CompareAndSwap requires the object to exist. Revert
			// the insert.
			idIndexTxn.delete(idKey)
			table.revision = oldRevision
			return object{}, false, watch, ErrObjectNotFound
		}
		if oldObj.revision != guardRevision {
			// Revert the change. We're assuming here that it's rarer for CompareAndSwap() to
			// fail and thus we're optimizing to have only one lookup in the common case
			// (versus doing a Get() and then Insert()).
			idIndexTxn.insert(idKey, oldObj)
			table.revision = oldRevision
			return oldObj, true, watch, ErrRevisionNotEqual
		}
	}

	// Update revision index
	revIndexTxn := txn.mustIndexWriteTxn(meta, RevisionIndexPos)
	if oldExists {
		binary.BigEndian.PutUint64(txn.revKey[:], oldObj.revision)
		revIndexTxn.delete(txn.revKey[:])
	}
	revIndexTxn.insert(index.Uint64(obj.revision), obj)

	// If it's new, possibly remove an older deleted object with the same
	// primary key from the graveyard.
	if !oldExists {
		if old, _, existed := txn.mustIndexReadTxn(meta, GraveyardIndexPos).get(idKey); existed {
			txn.mustIndexWriteTxn(meta, GraveyardIndexPos).delete(idKey)
			binary.BigEndian.PutUint64(txn.revKey[:], old.revision)
			txn.mustIndexWriteTxn(meta, GraveyardRevisionIndexPos).delete(txn.revKey[:])
		}
	}

	// Then update secondary indexes
	for _, indexer := range meta.secondary() {
		indexTxn := txn.mustIndexWriteTxn(meta, indexer.pos)
		indexTxn.reindex(idKey, oldObj, obj)
	}

	return oldObj, oldExists, watch, nil
}

func (txn *writeTxnState) hasDeleteTrackers(meta TableMeta) bool {
	table := txn.tableEntries[meta.tablePos()]
	return table.deleteTrackers.Len() > 0
}

func (txn *writeTxnState) addDeleteTracker(meta TableMeta, trackerName string, dt anyDeleteTracker) error {
	if txn == nil {
		return ErrTransactionClosed
	}
	table := txn.tableEntries[meta.tablePos()]
	if !table.locked {
		return tableError(meta.Name(), ErrTableNotLockedForWriting)
	}

	_, _, updated := table.deleteTrackers.Insert([]byte(trackerName), dt)
	table.deleteTrackers = &updated
	txn.db.metrics.DeleteTrackerCount(meta.Name(), table.deleteTrackers.Len())

	return nil
}

func (txn *writeTxnState) delete(meta TableMeta, guardRevision Revision, data any) (object, bool, error) {
	if txn == nil {
		return object{}, false, ErrTransactionClosed
	}

	// Look up table and allocate a new revision.
	tableName := meta.Name()
	table := txn.tableEntries[meta.tablePos()]
	if !table.locked {
		return object{}, false, tableError(tableName, ErrTableNotLockedForWriting)
	}
	oldRevision := table.revision
	table.revision++
	revision := table.revision

	// Delete from the primary index first to grab the object.
	// We assume that "data" has only enough defined fields to
	// compute the primary key.
	idIndex := txn.mustIndexWriteTxn(meta, PrimaryIndexPos)
	idKey := idIndex.objectToKey(object{data: data})
	obj, existed := idIndex.delete(idKey)
	if !existed {
		return object{}, false, nil
	}

	// For CompareAndDelete() validate against guard revision and if there's a mismatch,
	// revert the change.
	if guardRevision > 0 {
		if obj.revision != guardRevision {
			idIndex.insert(idKey, obj)
			table.revision = oldRevision
			return obj, true, ErrRevisionNotEqual
		}
	}

	// Remove the object from the revision index.
	binary.BigEndian.PutUint64(txn.revKey[:], obj.revision)
	txn.mustIndexWriteTxn(meta, RevisionIndexPos).delete(txn.revKey[:])

	// Then update secondary indexes.
	for _, indexer := range meta.secondary() {
		txn.mustIndexWriteTxn(meta, indexer.pos).reindex(idKey, obj, object{})
	}

	// And finally insert the object into the graveyard.
	if txn.hasDeleteTrackers(meta) {
		graveyardIndex := txn.mustIndexWriteTxn(meta, GraveyardIndexPos)
		obj.revision = revision
		if _, existed, _ := graveyardIndex.insert(idKey, obj); existed {
			panic("BUG: Double deletion! Deleted object already existed in graveyard")
		}
		txn.mustIndexWriteTxn(meta, GraveyardRevisionIndexPos).insert(index.Uint64(revision), obj)
	}

	return obj, true, nil
}

// returnToPool clears all fields of [writeTxnState], except the ones used for statistics
// and returns it to the pool.
func (handle *writeTxnHandle) returnToPool() {
	txn := handle.writeTxnState
	txn.tableEntries = nil
	txn.numTxns = 0
	clear(txn.smus)
	txn.smus = txn.smus[:0]
	clear(txn.tableNames)
	txn.tableNames = txn.tableNames[:0]
	txn.db.writeTxnPool.Put(txn)
	handle.writeTxnState = nil
	runtime.SetFinalizer(handle, nil)
}

func (handle *writeTxnHandle) Abort() {
	// If modifiedTables is nil, this transaction has already been committed or aborted, and
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
	if handle.writeTxnState == nil {
		// Already Abort()'d or Commit()'d
		return
	}

	txn := handle.writeTxnState
	for _, table := range txn.tableEntries {
		if table.locked {
			table.meta.released()
		}
	}

	txn.duration.Store(uint64(time.Since(txn.acquiredAt)))

	txn.smus.Unlock()
	txn.db.metrics.WriteTxnDuration(
		txn.handle,
		txn.tableNames,
		time.Since(txn.acquiredAt))
	handle.returnToPool()
}

// Commit the transaction. Returns a ReadTxn that is the snapshot of the database at the
// point of commit.
func (handle *writeTxnHandle) Commit() ReadTxn {
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

	if handle.writeTxnState == nil {
		return nil
	}
	txn := handle.writeTxnState

	txn.duration.Store(uint64(time.Since(txn.acquiredAt)))

	db := txn.db

	// Commit each individual changed index to each table.
	// We don't notify yet (CommitOnly) as the root needs to be updated
	// first as otherwise readers would wake up too early.
	txnToNotify := make([]tableIndexTxnNotify, 0, txn.numTxns)
	for pos := range txn.tableEntries {
		table := txn.tableEntries[pos]
		if !table.locked {
			continue
		}
		for i, idx := range table.indexes {
			var txn tableIndexTxnNotify
			table.indexes[i], txn = idx.commit()
			if txn != nil {
				txnToNotify = append(txnToNotify, txn)
			}
		}

		// Update metrics
		name := table.meta.Name()
		db.metrics.GraveyardObjectCount(name, table.numDeletedObjects())
		db.metrics.ObjectCount(name, table.numObjects())
		db.metrics.Revision(name, table.revision)
	}

	// Acquire the lock on the root tree to sequence the updates to it. We can acquire
	// it after we've built up the new table entries above, since changes to those were
	// protected by each table lock (that we're holding here).
	db.mu.Lock()

	// Since the root may have changed since the pointer was last read in WriteTxn(),
	// load it again and modify the latest version that we now have immobilised by
	// the root lock.
	currentRoot := *db.root.Load()
	root := txn.tableEntries
	var initChansToClose []chan struct{}

	// Insert the modified tables into the root tree of tables.
	for pos := range txn.tableEntries {
		table := txn.tableEntries[pos]
		if !table.locked {
			// Table was not locked so it might have changed.
			// Update the entry from the current root.
			root[pos] = currentRoot[pos]
			continue
		}
		// Check if tables become initialized. We close the channel only after
		// we've swapped in the new root so that one cannot get a snapshot of
		// an uninitialized table after observing the channel closing.
		if init := table.init; init != nil {
			if len(init.pending) == 0 {
				initChansToClose = append(initChansToClose, init.watch)
				table.init = nil
			}
		}
		table.meta.released()
		table.locked = false
	}
	txn.tableEntries = nil

	// Commit the transaction to build the new root tree and then
	// atomically store it.
	db.root.Store(&root)
	db.mu.Unlock()

	// Now that new root is committed, we can notify readers by closing the watch channels of
	// mutated radix tree nodes in all changed indexes and on the root itself.
	for _, txn := range txnToNotify {
		txn.notify()
	}

	// With the root pointer updated, we can now release the tables for the next write transaction.
	txn.smus.Unlock()

	// Notify table initializations
	for _, ch := range initChansToClose {
		close(ch)
	}

	txn.db.metrics.WriteTxnDuration(
		txn.handle,
		txn.tableNames,
		time.Since(txn.acquiredAt))

	handle.returnToPool()

	handle.readTxn = root
	return &handle.readTxn
}

// WriteJSON marshals out the database as JSON into the given writer.
// If tables are given then only these tables are written.
func (txn *writeTxnState) WriteJSON(w io.Writer, tables ...string) error {
	rtxn := readTxn(txn.tableEntries)
	return rtxn.WriteJSON(w, tables...)
}
