// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/internal"
	"github.com/cilium/statedb/part"
)

type writeTxn struct {
	db     *DB
	dbRoot dbRoot

	handle     string
	acquiredAt time.Time     // the time at which the transaction acquired the locks
	duration   atomic.Uint64 // the transaction duration after it finished

	modifiedTables []*tableEntry            // table entries being modified
	smus           internal.SortableMutexes // the (sorted) table locks
	tableNames     []string
}

type indexReadTxn struct {
	part.Ops[object]
	unique bool
}

type indexTxn struct {
	*part.Txn[object]
	unique bool
}

func (txn *writeTxn) getTxn() *writeTxn {
	return txn
}

func (txn *writeTxn) root() dbRoot {
	return txn.dbRoot
}

// acquiredInfo returns the information for the "Last WriteTxn" column
// in "db tables" command. The correctness of this relies on the following assumptions:
// - txn.handle and txn.acquiredAt are not modified
// - txn.duration is atomically updated on Commit or Abort
func (txn *writeTxn) acquiredInfo() string {
	if txn == nil {
		return ""
	}
	since := internal.PrettySince(txn.acquiredAt)
	dur := time.Duration(txn.duration.Load())
	if txn.duration.Load() == 0 {
		// Still locked
		return fmt.Sprintf("%s (locked for %s)", txn.handle, since)
	}
	return fmt.Sprintf("%s (%s ago, locked for %s)", txn.handle, since, internal.PrettyDuration(dur))
}

// txnFinalizer is called when the GC frees *txn. It checks that a WriteTxn
// has been Aborted or Committed. This is a safeguard against forgetting to
// Abort/Commit which would cause the table to be locked forever.
func txnFinalizer(txn *writeTxn) {
	if txn.modifiedTables != nil {
		panic(fmt.Sprintf("WriteTxn from handle %s against tables %v was never Abort()'d or Commit()'d", txn.handle, txn.tableNames))
	}
}

func (txn *writeTxn) getTableEntry(meta TableMeta) *tableEntry {
	if txn.modifiedTables != nil {
		entry := txn.modifiedTables[meta.tablePos()]
		if entry != nil {
			return entry
		}
	}
	return &txn.dbRoot[meta.tablePos()]
}

// indexReadTxn returns a transaction to read from the specific index.
// If the table or index is not found this returns nil & error.
func (txn *writeTxn) indexReadTxn(meta TableMeta, indexPos int) (indexReadTxn, error) {
	if meta.tablePos() < 0 {
		return indexReadTxn{}, tableError(meta.Name(), ErrTableNotRegistered)
	}
	if txn.modifiedTables != nil {
		entry := txn.modifiedTables[meta.tablePos()]
		if entry != nil {
			indexEntry := &entry.indexes[indexPos]
			// Since iradix reuses nodes when mutating we need to return a clone
			// so that iterators don't become invalid.
			return indexReadTxn{indexEntry.getClone(), indexEntry.unique}, nil
		}
	}
	indexEntry := txn.dbRoot[meta.tablePos()].indexes[indexPos]
	return indexReadTxn{indexEntry.tree, indexEntry.unique}, nil
}

// indexWriteTxn returns a transaction to read/write to a specific index.
// The created transaction is memoized and used for subsequent reads and/or writes.
func (txn *writeTxn) indexWriteTxn(meta TableMeta, indexPos int) (indexTxn, error) {
	table := txn.modifiedTables[meta.tablePos()]
	if table == nil {
		return indexTxn{}, tableError(meta.Name(), ErrTableNotLockedForWriting)
	}
	indexEntry := &table.indexes[indexPos]
	if indexEntry.txn == nil {
		indexEntry.txn = indexEntry.tree.Txn()
	}
	indexEntry.clone = nil
	return indexTxn{indexEntry.txn, indexEntry.unique}, nil
}

// mustIndexReadTxn returns a transaction to read from the specific index.
// Panics if table or index are not found.
func (txn *writeTxn) mustIndexReadTxn(meta TableMeta, indexPos int) indexReadTxn {
	indexTxn, err := txn.indexReadTxn(meta, indexPos)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

// mustIndexReadTxn returns a transaction to read or write from the specific index.
// Panics if table or index not found.
func (txn *writeTxn) mustIndexWriteTxn(meta TableMeta, indexPos int) indexTxn {
	indexTxn, err := txn.indexWriteTxn(meta, indexPos)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

func (txn *writeTxn) insert(meta TableMeta, guardRevision Revision, data any) (object, bool, <-chan struct{}, error) {
	return txn.modify(meta, guardRevision, data, func(_ any) any { return data })
}

func (txn *writeTxn) modify(meta TableMeta, guardRevision Revision, newData any, merge func(any) any) (object, bool, <-chan struct{}, error) {
	if txn.modifiedTables == nil {
		return object{}, false, nil, ErrTransactionClosed
	}

	// Look up table and allocate a new revision.
	tableName := meta.Name()
	table := txn.modifiedTables[meta.tablePos()]
	if table == nil {
		return object{}, false, nil, tableError(tableName, ErrTableNotLockedForWriting)
	}
	oldRevision := table.revision
	table.revision++
	revision := table.revision

	// Update the primary index first
	idKey := meta.primary().fromObject(object{data: newData}).First()
	idIndexTxn := txn.mustIndexWriteTxn(meta, PrimaryIndexPos)

	var obj object
	oldObj, oldExists, watch := idIndexTxn.ModifyWatch(idKey,
		func(old object) object {
			obj = object{
				revision: revision,
			}
			if old.revision == 0 {
				// Zero revision: the object did not exist so no need to call merge.
				obj.data = newData
			} else {
				obj.data = merge(old.data)
			}
			return obj
		})

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
			idIndexTxn.Delete(idKey)
			table.revision = oldRevision
			return object{}, false, watch, ErrObjectNotFound
		}
		if oldObj.revision != guardRevision {
			// Revert the change. We're assuming here that it's rarer for CompareAndSwap() to
			// fail and thus we're optimizing to have only one lookup in the common case
			// (versus doing a Get() and then Insert()).
			idIndexTxn.Insert(idKey, oldObj)
			table.revision = oldRevision
			return oldObj, true, watch, ErrRevisionNotEqual
		}
	}

	// Update revision index
	revIndexTxn := txn.mustIndexWriteTxn(meta, RevisionIndexPos)
	if oldExists {
		var revKey [8]byte // to avoid heap allocation
		binary.BigEndian.PutUint64(revKey[:], oldObj.revision)
		_, ok := revIndexTxn.Delete(revKey[:])
		if !ok {
			panic("BUG: Old revision index entry not found")
		}
	}
	revIndexTxn.Insert(index.Uint64(obj.revision), obj)

	// If it's new, possibly remove an older deleted object with the same
	// primary key from the graveyard.
	if !oldExists {
		if old, existed := txn.mustIndexWriteTxn(meta, GraveyardIndexPos).Delete(idKey); existed {
			var revKey [8]byte // to avoid heap allocation
			binary.BigEndian.PutUint64(revKey[:], old.revision)
			txn.mustIndexWriteTxn(meta, GraveyardRevisionIndexPos).Delete(revKey[:])
		}
	}

	// Then update secondary indexes
	for _, indexer := range meta.secondary() {
		indexTxn := txn.mustIndexWriteTxn(meta, indexer.pos)
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

	return oldObj, oldExists, watch, nil
}

func (txn *writeTxn) hasDeleteTrackers(meta TableMeta) bool {
	table := txn.modifiedTables[meta.tablePos()]
	if table != nil {
		return table.deleteTrackers.Len() > 0
	}
	return txn.dbRoot[meta.tablePos()].deleteTrackers.Len() > 0
}

func (txn *writeTxn) addDeleteTracker(meta TableMeta, trackerName string, dt anyDeleteTracker) error {
	if txn.modifiedTables == nil {
		return ErrTransactionClosed
	}
	table := txn.modifiedTables[meta.tablePos()]
	if table == nil {
		return tableError(meta.Name(), ErrTableNotLockedForWriting)
	}

	_, _, table.deleteTrackers = table.deleteTrackers.Insert([]byte(trackerName), dt)
	txn.db.metrics.DeleteTrackerCount(meta.Name(), table.deleteTrackers.Len())

	return nil
}

func (txn *writeTxn) delete(meta TableMeta, guardRevision Revision, data any) (object, bool, error) {
	if txn.modifiedTables == nil {
		return object{}, false, ErrTransactionClosed
	}

	// Look up table and allocate a new revision.
	tableName := meta.Name()
	table := txn.modifiedTables[meta.tablePos()]
	if table == nil {
		return object{}, false, tableError(tableName, ErrTableNotLockedForWriting)
	}
	oldRevision := table.revision
	table.revision++
	revision := table.revision

	// Delete from the primary index first to grab the object.
	// We assume that "data" has only enough defined fields to
	// compute the primary key.
	idKey := meta.primary().fromObject(object{data: data}).First()
	idIndexTree := txn.mustIndexWriteTxn(meta, PrimaryIndexPos)
	obj, existed := idIndexTree.Delete(idKey)
	if !existed {
		return object{}, false, nil
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

	// Remove the object from the revision index.
	indexTree := txn.mustIndexWriteTxn(meta, RevisionIndexPos)
	var revKey [8]byte // To avoid heap allocation
	binary.BigEndian.PutUint64(revKey[:], obj.revision)
	if _, ok := indexTree.Delete(revKey[:]); !ok {
		txn.Abort()
		panic("BUG: Object to be deleted not found from revision index")
	}

	// Then update secondary indexes.
	for _, indexer := range meta.secondary() {
		indexer.fromObject(obj).Foreach(func(key index.Key) {
			if !indexer.unique {
				key = encodeNonUniqueKey(idKey, key)
			}
			txn.mustIndexWriteTxn(meta, indexer.pos).Delete(key)
		})
	}

	// And finally insert the object into the graveyard.
	if txn.hasDeleteTrackers(meta) {
		graveyardIndex := txn.mustIndexWriteTxn(meta, GraveyardIndexPos)
		obj.revision = revision
		if _, existed := graveyardIndex.Insert(idKey, obj); existed {
			txn.Abort()
			panic("BUG: Double deletion! Deleted object already existed in graveyard")
		}
		txn.mustIndexWriteTxn(meta, GraveyardRevisionIndexPos).Insert(index.Uint64(revision), obj)
	}

	return obj, true, nil
}

// reset clears all fields of [writeTxn], except the ones used for statistics.
func (txn *writeTxn) reset() {
	txn.db = nil
	txn.dbRoot = nil
	txn.modifiedTables = nil
	txn.smus = nil
	txn.tableNames = nil
}

const (
	// nonUniqueSeparator is the byte that delimits the secondary and primary keys.
	// It has to be 0x00 for correct ordering, e.g. if secondary prefix is "ab",
	// then it must hold that "ab<sep>" < "abc<sep>", which is only possible if sep=0x00.
	nonUniqueSeparator = 0x00

	// nonUniqueSubstitute is the byte that is used to escape 0x00 and 0x01 in
	// order to make sure the non-unique key has only a single 0x00 byte that is
	// the separator.
	nonUniqueSubstitute = 0x01
)

// appendEncode encodes the 'src' into 'dst'.
func appendEncode(dst, src []byte) (int, []byte) {
	n := 0
	for _, b := range src {
		switch b {
		case nonUniqueSeparator:
			dst = append(dst, nonUniqueSubstitute, 0x01)
			n += 2
		case nonUniqueSubstitute:
			dst = append(dst, nonUniqueSubstitute, 0x02)
			n += 2
		default:
			dst = append(dst, b)
			n++
		}
	}
	return n, dst
}

func encodedLength(src []byte) int {
	n := len(src)
	for _, b := range src {
		if b == nonUniqueSeparator || b == nonUniqueSubstitute {
			n++
		}
	}
	return n
}

func encodeNonUniqueBytes(src []byte) []byte {
	n := encodedLength(src)
	if n == len(src) {
		// No substitutions needed.
		return src
	}
	_, out := appendEncode(make([]byte, 0, n), src)
	return out
}

// encodeNonUniqueKey constructs the internal key to use with non-unique indexes.
//
// This schema allows looking up from the non-unique index with the secondary key by
// doing a prefix search. The length is used to safe-guard against indexers that don't
// terminate the key properly (e.g. if secondary key is "foo", then we don't want
// "foobar" to match).
func encodeNonUniqueKey(primary, secondary index.Key) []byte {
	key := make([]byte, 0,
		encodedLength(secondary)+
			1 /* delimiter */ +
			encodedLength(primary)+
			2 /* primary length */)

	_, key = appendEncode(key, secondary)
	key = append(key, 0x00)
	primaryLen, key := appendEncode(key, primary)
	return binary.BigEndian.AppendUint16(key, uint16(primaryLen))
}

type nonUniqueKey []byte

func (k nonUniqueKey) primaryLen() int {
	// Non-unique key is [<secondary...>, 0x00, <primary...>, <primary length>]
	if len(k) <= 3 {
		return 0
	}
	return int(binary.BigEndian.Uint16(k[len(k)-2:]))
}

func (k nonUniqueKey) secondaryLen() int {
	return len(k) - k.primaryLen() - 3
}

func (k nonUniqueKey) encodedPrimary() []byte {
	primaryLen := k.primaryLen()
	return k[len(k)-2-primaryLen : len(k)-2]
}

func (k nonUniqueKey) encodedSecondary() []byte {
	return k[:k.secondaryLen()]
}

func (txn *writeTxn) Abort() {
	runtime.SetFinalizer(txn, nil)

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
	if txn.modifiedTables == nil {
		return
	}

	txn.duration.Store(uint64(time.Since(txn.acquiredAt)))

	txn.smus.Unlock()
	txn.db.metrics.WriteTxnDuration(
		txn.handle,
		txn.tableNames,
		time.Since(txn.acquiredAt))

	txn.reset()
}

// Commit the transaction. Returns a ReadTxn that is the snapshot of the database at the
// point of commit.
func (txn *writeTxn) Commit() ReadTxn {
	runtime.SetFinalizer(txn, nil)

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

	// If db is nil, this transaction has already been committed or aborted, and
	// thus there is nothing to do.
	if txn.db == nil {
		return nil
	}

	txn.duration.Store(uint64(time.Since(txn.acquiredAt)))

	db := txn.db

	// Commit each individual changed index to each table.
	// We don't notify yet (CommitOnly) as the root needs to be updated
	// first as otherwise readers would wake up too early.
	txnToNotify := []*part.Txn[object]{}
	for _, table := range txn.modifiedTables {
		if table == nil {
			continue
		}
		for i := range table.indexes {
			txn := table.indexes[i].txn
			if txn != nil {
				table.indexes[i].tree = txn.CommitOnly()
				table.indexes[i].txn = nil
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
	root := *db.root.Load()
	root = slices.Clone(root)

	var initChansToClose []chan struct{}

	// Insert the modified tables into the root tree of tables.
	for pos, table := range txn.modifiedTables {
		if table != nil {
			// Check if tables become initialized. We close the channel only after
			// we've swapped in the new root so that one cannot get a snapshot of
			// an uninitialized table after observing the channel closing.
			if !table.initialized && len(table.pendingInitializers) == 0 {
				initChansToClose = append(initChansToClose, table.initWatchChan)
				table.initialized = true
			}
			root[pos] = *table
		}
	}

	// Commit the transaction to build the new root tree and then
	// atomically store it.
	txn.dbRoot = root
	db.root.Store(&root)
	db.mu.Unlock()

	// Now that new root is committed, we can notify readers by closing the watch channels of
	// mutated radix tree nodes in all changed indexes and on the root itself.
	for _, txn := range txnToNotify {
		txn.Notify()
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

	txn.reset()
	return readTxn(root)
}

// WriteJSON marshals out the database as JSON into the given writer.
// If tables are given then only these tables are written.
func (txn *writeTxn) WriteJSON(w io.Writer, tables ...string) error {
	return readTxn(txn.dbRoot).WriteJSON(w, tables...)
}
