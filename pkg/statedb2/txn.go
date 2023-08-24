// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/lock"
)

type txn struct {
	db                     *DB
	rootReadTxn            *iradix.Txn[tableEntry]            // read transaction onto the tree of tables
	lastIndexReadTxn       lastIndexReadTxn                   // memoized result of the last indexReadTxn()
	writeTxns              map[tableIndex]*iradix.Txn[object] // opened per-index write transactions
	tables                 map[TableName]*tableEntry          // table entries being modified
	smus                   lock.SortableMutexes               // the (sorted) table locks
	acquiredAt             time.Time                          // the time at which the transaction acquired the locks
	tableNames             string                             // plus-separated list of table names
	packageName            string                             // name of the package that created the transaction
	pendingObjectDeltas    map[TableName]float64              // the change in the number of objects made by this txn
	pendingGraveyardDeltas map[TableName]float64              // the change in the number of graveyard objects made by this txn
}

type tableIndex struct {
	table TableName
	index IndexName
}

type lastIndexReadTxn struct {
	table TableName
	index IndexName
	txn   *iradix.Txn[object]
}

var zeroTxn = txn{}

func revisionKey(rev uint64, idKey []byte) []byte {
	buf := make([]byte, 8+len(idKey))
	binary.BigEndian.PutUint64(buf, rev)
	copy(buf[8:], idKey)
	return buf
}

// txn fulfills the ReadTxn/WriteTxn interface.
func (txn *txn) getTxn() *txn {
	return txn
}

func (txn *txn) GetRevision(name TableName) Revision {
	if table, ok := txn.tables[name]; ok {
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
func (txn *txn) indexReadTxn(name TableName, index IndexName) *iradix.Txn[object] {
	if txn.writeTxns != nil {
		indexTxn, ok := txn.writeTxns[tableIndex{name, index}]
		if ok {
			return indexTxn.Clone()
		}
		if _, ok := txn.tables[name]; ok {
			// We're writing into this table, create a write transaction
			// instead.
			return txn.indexWriteTxn(name, index).Clone()
		}
	}

	if txn.lastIndexReadTxn.table == name && txn.lastIndexReadTxn.index == index {
		return txn.lastIndexReadTxn.txn
	}

	table, ok := txn.rootReadTxn.Get([]byte(name))
	if !ok {
		panic("BUG: Table '" + name + "' not found")
	}
	indexTree, ok := table.indexes.Get([]byte(index))
	if !ok {
		panic(fmt.Sprintf("BUG: Index %s/%s not found", name, index))
	}

	indexTxn := indexTree.Txn()
	txn.lastIndexReadTxn = lastIndexReadTxn{table: name, index: index, txn: indexTxn}
	return indexTxn
}

// indexWriteTxn returns a transaction to read/write to a specific index.
// The created transaction is memoized and used for subsequent reads and/or writes.
func (txn *txn) indexWriteTxn(name TableName, index IndexName) *iradix.Txn[object] {
	if indexTreeTxn, ok := txn.writeTxns[tableIndex{name, index}]; ok {
		return indexTreeTxn
	}
	table, ok := txn.tables[name]
	if !ok {
		panic("BUG: Table '" + name + "' not found")
	}
	indexTree, ok := table.indexes.Get([]byte(index))
	if !ok {
		panic(fmt.Sprintf("BUG: Index %s/%s not found", name, index))
	}
	indexTreeTxn := indexTree.Txn()
	indexTreeTxn.TrackMutate(true)
	txn.writeTxns[tableIndex{name, index}] = indexTreeTxn
	return indexTreeTxn
}

func (txn *txn) newRevision(tableName TableName) (Revision, error) {
	table, ok := txn.tables[tableName]
	if !ok {
		return 0, fmt.Errorf("table %q not locked for writing", tableName)
	}
	table.revision++
	txn.db.metrics.TableRevision.With(prometheus.Labels{
		"table": tableName,
	}).Set(float64(table.revision))
	return table.revision, nil
}

func (txn *txn) Insert(meta TableMeta, data any) (any, bool, error) {
	if txn.rootReadTxn == nil {
		return nil, false, fmt.Errorf("transaction is closed")
	}

	tableName := meta.Name()
	revision, err := txn.newRevision(tableName)
	if err != nil {
		return nil, false, err
	}

	obj := object{
		revision: revision,
		data:     data,
	}

	// Update the primary index first
	idKey := meta.primaryIndexer().fromObject(obj).First()
	idIndexTree := txn.indexWriteTxn(tableName, meta.primaryIndexer().name)
	oldObj, oldExists := idIndexTree.Insert(idKey, obj)

	// Update revision index
	revIndexTree := txn.indexWriteTxn(tableName, RevisionIndex)
	if oldExists {
		_, ok := revIndexTree.Delete(revisionKey(oldObj.revision, idKey))
		if !ok {
			panic("BUG: Old revision index entry not found")
		}

		txn.pendingObjectDeltas[tableName]--
	}
	revIndexTree.Insert(revisionKey(revision, idKey), obj)
	txn.pendingObjectDeltas[tableName]++

	// If it's new, possibly remove an older deleted object with the same
	// primary key from the graveyard.
	if !oldExists && txn.hasDeleteTrackers(tableName) {
		if old, existed := txn.indexWriteTxn(tableName, GraveyardIndex).Delete(idKey); existed {
			txn.indexWriteTxn(tableName, GraveyardRevisionIndex).Delete(revisionKey(old.revision, idKey))
			txn.pendingGraveyardDeltas[tableName]--
		}
	}

	// Then update secondary indexes
	for index, indexer := range meta.secondaryIndexers() {
		indexTree := txn.indexWriteTxn(tableName, index)
		newKeys := indexer.fromObject(obj)

		if oldExists {
			// If the object already existed it might've invalidated the
			// non-primary indexes. Compute the old key for this index and
			// if the new key is different delete the old entry.
			indexer.fromObject(oldObj).Foreach(func(oldKey []byte) {
				if !indexer.unique {
					oldKey = append(oldKey, idKey...)
				}
				if !newKeys.Exists(oldKey) {
					indexTree.Delete(oldKey)
				}
			})
		}
		newKeys.Foreach(func(newKey []byte) {
			// Non-unique secondary indexes are formed by concatenating them
			// with the primary key.
			if !indexer.unique {
				newKey = append(newKey, idKey...)
			}
			indexTree.Insert(newKey, obj)
		})
	}

	return oldObj.data, oldExists, nil
}

func (txn *txn) hasDeleteTrackers(name TableName) bool {
	return txn.getTable(name).deleteTrackers.Len() > 0
}

func (txn *txn) getTable(name TableName) *tableEntry {
	table, ok := txn.tables[name]
	if ok {
		return table
	}
	if t, ok := txn.rootReadTxn.Get([]byte(name)); ok {
		return &t
	}
	panic(fmt.Sprintf("BUG: table %q not found", name))
}

func (txn *txn) addDeleteTracker(meta TableMeta, trackerName string, dt deleteTracker) error {
	if txn.rootReadTxn == nil {
		return fmt.Errorf("transaction is closed")
	}
	table, ok := txn.tables[meta.Name()]
	if !ok {
		return fmt.Errorf("table %q not locked for writing", meta.Name())
	}
	dt.setRevision(table.revision)
	table.deleteTrackers, _, _ = table.deleteTrackers.Insert([]byte(trackerName), dt)
	txn.db.metrics.TableDeleteTrackerCount.With(prometheus.Labels{
		"table": meta.Name(),
	}).Inc()
	return nil

}

func (txn *txn) Delete(meta TableMeta, data any) (any, bool, error) {
	if txn.rootReadTxn == nil {
		return nil, false, fmt.Errorf("transaction is closed")
	}

	tableName := meta.Name()
	revision, err := txn.newRevision(tableName)
	if err != nil {
		return nil, false, err
	}

	// Delete from the primary index first to grab the object.
	// We assume that "data" has only enough defined fields to
	// compute the primary key.
	idKey := meta.primaryIndexer().fromObject(object{data: data}).First()
	idIndexTree := txn.indexWriteTxn(tableName, meta.primaryIndexer().name)
	obj, existed := idIndexTree.Delete(idKey)
	if !existed {
		return nil, false, fmt.Errorf("object not found")
	}

	txn.pendingObjectDeltas[tableName]--

	// Update revision index.
	indexTree := txn.indexWriteTxn(tableName, RevisionIndex)
	if _, ok := indexTree.Delete(revisionKey(obj.revision, idKey)); !ok {
		panic("BUG: Revision entry not found")
	}

	// Then update secondary indexes.
	for index, indexer := range meta.secondaryIndexers() {
		indexer.fromObject(obj).Foreach(func(key []byte) {
			if !indexer.unique {
				key = append(key, idKey...)
			}
			txn.indexWriteTxn(tableName, index).Delete(key)
		})
	}

	// And finally insert the object into the graveyard.
	if txn.hasDeleteTrackers(tableName) {
		graveyardIndex := txn.indexWriteTxn(tableName, GraveyardIndex)
		obj.revision = revision
		if old, existed := graveyardIndex.Insert(idKey, obj); existed {
			txn.indexWriteTxn(tableName, GraveyardRevisionIndex).Delete(revisionKey(old.revision, idKey))
			txn.pendingGraveyardDeltas[tableName]--
		}
		txn.indexWriteTxn(tableName, GraveyardRevisionIndex).Insert(revisionKey(revision, idKey), obj)
		txn.pendingGraveyardDeltas[tableName]++
	}

	return obj.data, true, nil
}

func (txn *txn) Abort() {
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
	if txn.writeTxns == nil {
		return
	}

	// Commit each individual changed index to each table.
	// We don't notify yet (CommitOnly) as the root needs to be updated
	// first.
	for tableIndex, subTxn := range txn.writeTxns {
		table, ok := txn.tables[tableIndex.table]
		if !ok {
			panic("BUG: Table " + tableIndex.table + " not cached")
		}
		table.indexes, _, _ =
			table.indexes.Insert([]byte(tableIndex.index), subTxn.CommitOnly())
	}

	db := txn.db

	// Acquire the lock on the root tree to sequence the updates to it.
	db.mu.Lock()
	rootTxn := db.root.Load().Txn()

	// Insert the modified tables into the root.
	for name, table := range txn.tables {
		rootTxn.Insert([]byte(name), *table)
	}

	// Commit the new root.
	newRoot := rootTxn.CommitOnly()
	db.root.Store(newRoot)
	db.mu.Unlock()

	// Now that new root is available notify of the changes by closing the watch channels.
	for _, subTxn := range txn.writeTxns {
		subTxn.Notify()
	}
	rootTxn.Notify()

	txn.smus.Unlock()
	for name, delta := range txn.pendingObjectDeltas {
		db.metrics.TableObjectCount.With(prometheus.Labels{
			"table": name,
		}).Add(delta)
	}
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

		indexTxn := txn.getTxn().indexReadTxn(table.Name(), table.primaryIndexer().name)
		if indexTxn == nil {
			panic("BUG: Missing primary index " + table.primaryIndexer().name)
		}
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
