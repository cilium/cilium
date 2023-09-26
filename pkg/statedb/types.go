// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"io"

	iradix "github.com/hashicorp/go-immutable-radix/v2"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type (
	TableName = string
	IndexName = string
	Revision  = uint64
)

type Table[Obj any] interface {
	// TableMeta for querying table metadata that is independent of
	// 'Obj' type. Provides the database access to table's indexers.
	TableMeta

	// Revision of the table. Constant for a read transaction, but
	// increments in a write transaction on each Insert and Delete.
	Revision(ReadTxn) Revision

	// All returns an iterator for all objects in the table and a watch
	// channel that is closed when the table changes.
	All(ReadTxn) (Iterator[Obj], <-chan struct{})

	// Get returns an iterator for all objects matching the given query
	// and a watch channel that is closed if the query results are
	// invalidated by a write to the table.
	Get(ReadTxn, Query[Obj]) (Iterator[Obj], <-chan struct{})

	// First returns the first matching object for the query.
	First(ReadTxn, Query[Obj]) (obj Obj, rev Revision, found bool)

	// FirstWatch return the first matching object and a watch channel
	// that is closed if the query is invalidated.
	FirstWatch(ReadTxn, Query[Obj]) (obj Obj, rev Revision, watch <-chan struct{}, found bool)

	// Last returns the last matching object.
	Last(ReadTxn, Query[Obj]) (obj Obj, rev Revision, found bool)

	// LastWatch returns the last matching object and a watch channel
	// that is closed if the query is invalidated.
	LastWatch(ReadTxn, Query[Obj]) (obj Obj, rev Revision, watch <-chan struct{}, found bool)

	// LowerBound returns an iterator for objects that have a key
	// greater or equal to the query. The returned watch channel is closed
	// when anything in the table changes as more fine-grained notifications
	// are not possible with a lower bound search.
	LowerBound(ReadTxn, Query[Obj]) (iter Iterator[Obj], watch <-chan struct{})

	// Insert an object into the table. Returns the object that was
	// replaced if there was one. Error may be returned if the table
	// is not locked for writing or if the write transaction has already
	// been committed or aborted.
	//
	// Each inserted or updated object will be assigned a new unique
	// revision.
	Insert(WriteTxn, Obj) (oldObj Obj, hadOld bool, err error)

	// Delete an object from the table. Returns the object that was
	// deleted if there was one. Error may be returned if the table
	// is not locked for writing or if the write transaction has already
	// been committed or aborted.
	//
	// If the table is being tracked for deletions via DeleteTracker()
	// the deleted object is inserted into a graveyard index and garbage
	// collected when all delete trackers have consumed it. Each deleted
	// object in the graveyard has unique revision allowing interleaved
	// iteration of updates and deletions (see (*DeleteTracker[Obj]).Process).
	Delete(WriteTxn, Obj) (oldObj Obj, hadOld bool, err error)

	// DeleteAll deletes all objects from the table. Semantically the
	// same as All() + Delete().
	DeleteAll(WriteTxn) error

	// DeleteTracker creates a new delete tracker for the table
	// starting from the given revision.
	DeleteTracker(txn WriteTxn, trackerName string) (*DeleteTracker[Obj], error)
}

// TableMeta provides information about the table that is independent of
// the object type (the 'Obj' constraint).
type TableMeta interface {
	Name() TableName                          // The name of the table
	tableKey() index.Key                      // The radix key for the table in the root tree
	primaryIndexer() anyIndexer               // The untyped primary indexer for the table
	secondaryIndexers() map[string]anyIndexer // Secondary indexers (if any)
	sortableMutex() lock.SortableMutex        // The sortable mutex for locking the table for writing
}

// Iterator for iterating objects returned from queries.
type Iterator[Obj any] interface {
	// Next returns the next object and its revision if ok is true, otherwise
	// zero values to mean that the iteration has finished.
	Next() (obj Obj, rev Revision, ok bool)
}

type ReadTxn interface {
	getTxn() *txn

	// WriteJSON writes the contents of the database as JSON.
	WriteJSON(io.Writer) error
}

type WriteTxn interface {
	// WriteTxn is always also a ReadTxn
	ReadTxn

	// Abort the current transaction. All changes are disgarded.
	// It is safe to call Abort() after calling Commit(), e.g.
	// the following pattern is strongly encouraged to make sure
	// write transactions are always completed:
	//
	//  txn := db.WriteTxn(...)
	//  defer txn.Abort()
	//  ...
	//  txn.Commit()
	Abort()

	// Commit the changes in the current transaction to the target tables.
	// This is a no-op if Abort() or Commit() has already been called.
	Commit()
}

type Query[Obj any] struct {
	index  IndexName
	unique bool
	key    []byte
}

// ByRevision constructs a revision query. Applicable to any table.
func ByRevision[Obj any](rev uint64) Query[Obj] {
	return Query[Obj]{
		index:  RevisionIndex,
		unique: false,
		key:    index.Uint64(rev),
	}
}

// Index implements the indexing of objects (FromObjects) and querying of objects from the index (FromKey)
type Index[Obj any, Key any] struct {
	Name       string
	FromObject func(obj Obj) index.KeySet
	FromKey    func(key Key) []byte
	Unique     bool
}

var _ Indexer[struct{}] = &Index[struct{}, bool]{}

// The nolint:unused below are needed due to linter not seeing
// the use-sites due to generics.

//nolint:unused
func (i Index[Key, Obj]) indexName() string {
	return i.Name
}

//nolint:unused
func (i Index[Obj, Key]) fromObject(obj Obj) index.KeySet {
	return i.FromObject(obj)
}

//nolint:unused
func (i Index[Obj, Key]) isUnique() bool {
	return i.Unique
}

// Query constructs a query against this index from a key.
func (i Index[Obj, Key]) Query(key Key) Query[Obj] {
	return Query[Obj]{
		index:  i.Name,
		unique: i.isUnique(),
		key:    i.FromKey(key),
	}
}

// Indexer is the "FromObject" subset of Index[Obj, Key]
// without the 'Key' constraint.
type Indexer[Obj any] interface {
	indexName() string
	isUnique() bool
	fromObject(obj Obj) index.KeySet
}

//
// Internal types and constants.
//

const (
	reservedIndexPrefix    = "__"
	RevisionIndex          = "__revision__"
	GraveyardIndex         = "__graveyard__"
	GraveyardRevisionIndex = "__graveyard_revision__"
)

// object is the format in which data is stored in the tables.
type object struct {
	revision uint64
	data     any
}

// anyIndexer is an untyped indexer. The user-defined 'Index[Obj,Key]'
// is converted to this form.
type anyIndexer struct {
	// name is the indexer name.
	name string

	// fromObject returns the key (or keys for multi-index) to index the
	// object with.
	fromObject func(object) index.KeySet

	// unique if true will index the object solely on the
	// values returned by fromObject. If false the primary
	// key of the object will be appended to the key.
	unique bool
}

type deleteTracker interface {
	setRevision(uint64)
	getRevision() uint64
}

type indexTree = *iradix.Tree[object]

type tableEntry struct {
	meta           TableMeta
	indexes        *iradix.Tree[indexTree]
	deleteTrackers *iradix.Tree[deleteTracker]
	revision       uint64
}

func (t *tableEntry) numObjects() int {
	indexTree, ok := t.indexes.Get([]byte(RevisionIndex))
	if ok {
		return indexTree.Len()
	}
	return 0
}

func (t *tableEntry) numDeletedObjects() int {
	indexTree, ok := t.indexes.Get([]byte(GraveyardIndex))
	if ok {
		return indexTree.Len()
	}
	return 0
}
