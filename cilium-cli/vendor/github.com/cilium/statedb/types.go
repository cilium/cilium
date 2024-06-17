// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"io"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/internal"
	"github.com/cilium/statedb/part"
)

type (
	TableName = string
	IndexName = string
	Revision  = uint64
)

// Table provides methods for querying the contents of a table.
type Table[Obj any] interface {
	// TableMeta for querying table metadata that is independent of
	// 'Obj' type.
	TableMeta

	// PrimaryIndexer returns the primary indexer for the table.
	// Useful for generic utilities that need access to the primary key.
	PrimaryIndexer() Indexer[Obj]

	// NumObjects returns the number of objects stored in the table.
	NumObjects(ReadTxn) int

	// Initialized returns true if in this ReadTxn (snapshot of the database)
	// the registered initializers have all been completed.
	Initialized(ReadTxn) bool

	// PendingInitializers returns the set of pending initializers that
	// have not yet completed.
	PendingInitializers(ReadTxn) []string

	// Revision of the table. Constant for a read transaction, but
	// increments in a write transaction on each Insert and Delete.
	Revision(ReadTxn) Revision

	// All returns an iterator for all objects in the table and a watch
	// channel that is closed when the table changes.
	All(ReadTxn) (Iterator[Obj], <-chan struct{})

	// List returns an iterator for all objects matching the given query.
	List(ReadTxn, Query[Obj]) Iterator[Obj]

	// ListWatch returns an iterator for all objects matching the given query
	// and a watch channel that is closed if the query results are
	// invalidated by a write to the table.
	ListWatch(ReadTxn, Query[Obj]) (Iterator[Obj], <-chan struct{})

	// Get returns the first matching object for the query.
	Get(ReadTxn, Query[Obj]) (obj Obj, rev Revision, found bool)

	// GetWatch return the first matching object and a watch channel
	// that is closed if the query is invalidated.
	GetWatch(ReadTxn, Query[Obj]) (obj Obj, rev Revision, watch <-chan struct{}, found bool)

	// LowerBound returns an iterator for objects that have a key
	// greater or equal to the query. The returned watch channel is closed
	// when anything in the table changes as more fine-grained notifications
	// are not possible with a lower bound search.
	LowerBound(ReadTxn, Query[Obj]) (iter Iterator[Obj], watch <-chan struct{})

	// Prefix searches the table by key prefix.
	Prefix(ReadTxn, Query[Obj]) (iter Iterator[Obj], watch <-chan struct{})

	// Changes returns an iterator for changes happening to the table.
	// This uses the revision index to iterate over the objects in the order
	// they have changed. Deleted objects are placed onto a temporary index
	// (graveyard) where they live until all change iterators have observed
	// the deletion.
	//
	// If an object is created and deleted before the observer has iterated
	// over the creation then only the deletion is seen.
	Changes(WriteTxn) (ChangeIterator[Obj], error)
}

// Change is either an update or a delete of an object. Used by Changes() and
// the Observable().
type Change[Obj any] struct {
	Object   Obj
	Revision Revision
	Deleted  bool
}

type ChangeIterator[Obj any] interface {
	Iterator[Change[Obj]]

	// Watch refreshes the iteration with a new query and returns a watch channel to wait
	// for new changes after Next() has returned false.
	Watch(ReadTxn) <-chan struct{}

	// Close closes the iterator. This must be called when one is done using
	// the iterator as a tracker is created for deleted objects and the
	// deleted objects are held onto until all event iterators have observed
	// the deletion.
	Close()
}

// RWTable provides methods for modifying the table under a write transaction
// that targets this table.
type RWTable[Obj any] interface {
	// RWTable[Obj] is a superset of Table[Obj]. Queries made with a
	// write transaction return the fresh uncommitted modifications if any.
	Table[Obj]

	// RegisterInitializer registers an initializer to the table. Returns
	// a function to mark the initializer done. Once all initializers are
	// done, Table[*].Initialized() will return true.
	// This should only be used before the application has started.
	RegisterInitializer(txn WriteTxn, name string) func(WriteTxn)

	// ToTable returns the Table[Obj] interface. Useful with cell.Provide
	// to avoid the anonymous function:
	//
	//   cell.ProvidePrivate(NewMyTable), // RWTable
	//   cell.Invoke(statedb.Register[statedb.RWTable[Foo])
	//
	//   // with anononymous function:
	//   cell.Provide(func(t statedb.RWTable[Foo]) statedb.Table[Foo] { return t })
	//
	//   // with ToTable:
	//   cell.Provide(statedb.RWTable[Foo].ToTable),
	ToTable() Table[Obj]

	// Insert an object into the table. Returns the object that was
	// replaced if there was one.
	//
	// Possible errors:
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	//
	// Each inserted or updated object will be assigned a new unique
	// revision.
	Insert(WriteTxn, Obj) (oldObj Obj, hadOld bool, err error)

	// CompareAndSwap compares the existing object's revision against the
	// given revision and if equal it replaces the object.
	//
	// Possible errors:
	// - ErrRevisionNotEqual: the object has mismatching revision
	// - ErrObjectNotFound: object not found from the table
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	CompareAndSwap(WriteTxn, Revision, Obj) (oldObj Obj, hadOld bool, err error)

	// Delete an object from the table. Returns the object that was
	// deleted if there was one.
	//
	// If the table is being tracked for deletions via EventIterator()
	// the deleted object is inserted into a graveyard index and garbage
	// collected when all delete trackers have consumed it. Each deleted
	// object in the graveyard has unique revision allowing interleaved
	// iteration of updates and deletions.
	//
	// Possible errors:
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	Delete(WriteTxn, Obj) (oldObj Obj, hadOld bool, err error)

	// DeleteAll removes all objects in the table. Semantically the same as
	// All() + Delete(). See Delete() for more information.
	//
	// Possible errors:
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	DeleteAll(WriteTxn) error

	// CompareAndDelete compares the existing object's revision against the
	// given revision and if equal it deletes the object. If object is not
	// found 'hadOld' will be false and 'err' nil.
	//
	// Possible errors:
	// - ErrRevisionNotEqual: the object has mismatching revision
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	CompareAndDelete(WriteTxn, Revision, Obj) (oldObj Obj, hadOld bool, err error)
}

// TableMeta provides information about the table that is independent of
// the object type (the 'Obj' constraint).
type TableMeta interface {
	Name() TableName // The name of the table
	tableEntry() tableEntry
	tablePos() int
	setTablePos(int)
	indexPos(string) int
	tableKey() []byte                      // The radix key for the table in the root tree
	primary() anyIndexer                   // The untyped primary indexer for the table
	secondary() map[string]anyIndexer      // Secondary indexers (if any)
	sortableMutex() internal.SortableMutex // The sortable mutex for locking the table for writing
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
	WriteJSON(w io.Writer, tables ...string) error
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
	// Returns a ReadTxn for reading the database at the time of commit.
	Commit() ReadTxn
}

type Query[Obj any] struct {
	index IndexName
	key   index.Key
}

// ByRevision constructs a revision query. Applicable to any table.
func ByRevision[Obj any](rev uint64) Query[Obj] {
	return Query[Obj]{
		index: RevisionIndex,
		key:   index.Uint64(rev),
	}
}

// Index implements the indexing of objects (FromObjects) and querying of objects from the index (FromKey)
type Index[Obj any, Key any] struct {
	Name       string
	FromObject func(obj Obj) index.KeySet
	FromKey    func(key Key) index.Key
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
		index: i.Name,
		key:   i.FromKey(key),
	}
}

func (i Index[Obj, Key]) QueryFromObject(obj Obj) Query[Obj] {
	return Query[Obj]{
		index: i.Name,
		key:   i.FromObject(obj).First(),
	}
}

func (i Index[Obj, Key]) ObjectToKey(obj Obj) index.Key {
	return i.FromObject(obj).First()
}

// Indexer is the "FromObject" subset of Index[Obj, Key]
// without the 'Key' constraint.
type Indexer[Obj any] interface {
	indexName() string
	isUnique() bool
	fromObject(Obj) index.KeySet

	ObjectToKey(Obj) index.Key
	QueryFromObject(Obj) Query[Obj]
}

// TableWritable is a constraint for objects that implement tabular
// pretty-printing. Used in "cilium-dbg statedb" sub-commands.
type TableWritable interface {
	// TableHeader returns the header columns that are independent of the
	// object.
	TableHeader() []string

	// TableRow returns the row columns for this object.
	TableRow() []string
}

//
// Internal types and constants.
//

const (
	PrimaryIndexPos = 0

	reservedIndexPrefix       = "__"
	RevisionIndex             = "__revision__"
	RevisionIndexPos          = 1
	GraveyardIndex            = "__graveyard__"
	GraveyardIndexPos         = 2
	GraveyardRevisionIndex    = "__graveyard_revision__"
	GraveyardRevisionIndexPos = 3

	SecondaryIndexStartPos = 4
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

	// pos is the position of the index in [tableEntry.indexes]
	pos int
}

type anyDeleteTracker interface {
	setRevision(uint64)
	getRevision() uint64
	close()
}

type indexEntry struct {
	tree   *part.Tree[object]
	txn    *part.Txn[object]
	unique bool
}

type tableEntry struct {
	meta                TableMeta
	indexes             []indexEntry
	deleteTrackers      *part.Tree[anyDeleteTracker]
	revision            uint64
	pendingInitializers []string
}

func (t *tableEntry) numObjects() int {
	indexEntry := t.indexes[t.meta.indexPos(RevisionIndex)]
	return indexEntry.tree.Len()
}

func (t *tableEntry) numDeletedObjects() int {
	indexEntry := t.indexes[t.meta.indexPos(GraveyardIndex)]
	return indexEntry.tree.Len()
}
