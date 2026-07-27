// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"io"
	"iter"

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

	// All returns a sequence of all objects in the table.
	All(ReadTxn) iter.Seq2[Obj, Revision]

	// AllWatch returns a sequence of all objects in the table and a watch
	// channel that is closed when the table changes.
	AllWatch(ReadTxn) (iter.Seq2[Obj, Revision], <-chan struct{})

	// List returns a sequence of objects matching the given query.
	List(ReadTxn, Query[Obj]) iter.Seq2[Obj, Revision]

	// ListWatch returns an iterator for all objects matching the given query
	// and a watch channel that is closed if the query results are
	// invalidated by a write to the table.
	ListWatch(ReadTxn, Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{})

	// Get returns the first matching object for the query.
	Get(ReadTxn, Query[Obj]) (obj Obj, rev Revision, found bool)

	// GetWatch returns the first matching object and a watch channel
	// that is closed if the query is invalidated.
	GetWatch(ReadTxn, Query[Obj]) (obj Obj, rev Revision, watch <-chan struct{}, found bool)

	// LowerBound returns an iterator for objects that have a key
	// greater than or equal to the query.
	LowerBound(ReadTxn, Query[Obj]) iter.Seq2[Obj, Revision]

	// LowerBoundWatch returns an iterator for objects that have a key
	// greater than or equal to the query. The returned watch channel is closed
	// when anything in the table changes as more fine-grained notifications
	// are not possible with a lower bound search.
	LowerBoundWatch(ReadTxn, Query[Obj]) (seq iter.Seq2[Obj, Revision], watch <-chan struct{})

	// Prefix searches the table by key prefix.
	Prefix(ReadTxn, Query[Obj]) iter.Seq2[Obj, Revision]

	// PrefixWatch searches the table by key prefix. Returns an iterator and a watch
	// channel that closes when the query results have become stale.
	PrefixWatch(ReadTxn, Query[Obj]) (seq iter.Seq2[Obj, Revision], watch <-chan struct{})

	// Changes returns an iterator for changes happening to the table.
	// This uses the revision index to iterate over the objects in the order
	// they have changed. Deleted objects are placed onto a temporary index
	// (graveyard) where they live until all change iterators have observed
	// the deletion.
	//
	// If an object is created and deleted before the observer has iterated
	// over the creation then only the deletion is seen.
	//
	// If [ChangeIterator.Next] is called with a [WriteTxn] targeting the
	// table being observed then only the changes prior to that [WriteTxn]
	// are observed.
	Changes(WriteTxn) (ChangeIterator[Obj], error)
}

// ByRevision constructs a revision query. Applicable to any table.
func ByRevision[Obj any](rev uint64) Query[Obj] {
	return Query[Obj]{
		index: RevisionIndex,
		key:   index.Uint64(rev),
	}
}

// Change is either an update or a delete of an object. Used by Changes() and
// the Observable().
// The 'Revision' is carried also in the Change object so that it is also accessible
// via Observable.
type Change[Obj any] struct {
	Object   Obj      `json:"obj"`
	Revision Revision `json:"rev"`
	Deleted  bool     `json:"deleted,omitempty"`
}

type ChangeIterator[Obj any] interface {
	// Next returns the sequence of unobserved changes up to the given ReadTxn (snapshot) and
	// a watch channel.
	//
	// If changes are available Next returns a closed watch channel. Only once there are no further
	// changes available will a proper watch channel be returned.
	//
	// Next can be called again without fully consuming the sequence to pull in new changes.
	//
	// The returned sequence is a single-use sequence and subsequent calls will return
	// an empty sequence.
	//
	// If Next is called with a [WriteTxn] targeting the table being observed then only
	// the changes made prior to that [WriteTxn] are observed, e.g. we can only observe
	// committed changes.
	Next(ReadTxn) (iter.Seq2[Change[Obj], Revision], <-chan struct{})

	// Close the change iterator. Once all change iterators for a given table are closed
	// deleted objects for that table are no longer set aside for the change iterators.
	//
	// Calling this method is optional as each iterator has a finalizer that closes it.
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
	//   // with anonymous function:
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

	// InsertWatch inserts an object into the table. Returns the object that was
	// replaced if there was one and a watch channel that closes when the
	// object is modified again.
	//
	// Possible errors:
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	//
	// Each inserted or updated object will be assigned a new unique
	// revision.
	InsertWatch(WriteTxn, Obj) (oldObj Obj, hadOld bool, watch <-chan struct{}, err error)

	// Modify an existing object or insert a new object into the table. If an old object
	// exists the [merge] function is called with the old and new objects.
	//
	// Modify is semantically equal to Get + Insert, but avoids extra lookups making
	// it significantly more efficient.
	//
	// Possible errors:
	// - ErrTableNotLockedForWriting: table was not locked for writing
	// - ErrTransactionClosed: the write transaction already committed or aborted
	Modify(txn WriteTxn, new Obj, merge func(old, new Obj) Obj) (oldObj Obj, hadOld bool, err error)

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
	// If the table is being tracked for deletions via Changes()
	// the deleted object is inserted into a graveyard index and garbage
	// collected when all delete trackers have consumed it. Each deleted
	// object in the graveyard has a unique revision, allowing interleaved
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
	// given revision and if equal it deletes the object. If the object is
	// not found, hadOld is false and err is nil.
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
	// Name returns the name of the table
	Name() TableName

	// Indexes returns the names of the indexes
	Indexes() []string

	// NumObjects returns the number of objects stored in the table.
	NumObjects(ReadTxn) int

	// Initialized returns true if in this ReadTxn (snapshot of the database)
	// the registered initializers have all been completed. The returned
	// watch channel will be closed when the table becomes initialized.
	Initialized(ReadTxn) (bool, <-chan struct{})

	// PendingInitializers returns the set of pending initializers that
	// have not yet completed.
	PendingInitializers(ReadTxn) []string

	// Revision of the table. Constant for a read transaction, but
	// increments in a write transaction on each Insert and Delete.
	Revision(ReadTxn) Revision

	// Internal unexported methods used only internally.
	tableInternal
}

type ReadTxn interface {
	indexReadTxn(meta TableMeta, indexPos int) (tableIndexReader, error)
	mustIndexReadTxn(meta TableMeta, indexPos int) tableIndexReader
	getTableEntry(meta TableMeta) *tableEntry

	// root returns the database root. If this is a WriteTxn it returns
	// the current modified root.
	root() dbRoot

	// committedRoot returns the committed database root. If this is a
	// WriteTxn it returns the root snapshotted at the time the WriteTxn
	// was constructed and thus does not reflect any changes made in the
	// transaction.
	committedRoot() dbRoot

	// WriteJSON writes the contents of the database as JSON.
	WriteJSON(w io.Writer, tables ...string) error
}

type WriteTxn interface {
	// WriteTxn is always also a ReadTxn
	ReadTxn

	// Abort the current transaction. All changes are discarded.
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

	// unwrap returns the internal state
	unwrap() *writeTxnState
}

type Query[Obj any] struct {
	index IndexName
	key   index.Key
}

type Indexer[Obj any] interface {
	// QueryFromObject constructs a query from an object against the
	// primary index.
	QueryFromObject(Obj) Query[Obj]

	// ObjectToKey returns the primary key of the object.
	ObjectToKey(Obj) index.Key

	// isIndexerOf is a marker method to constrain the indexer to the 'Obj'
	// type which enforces that indexer of a wrong type is not used.
	isIndexerOf(Obj)

	isUnique() bool
	indexName() string
	fromString(string) (index.Key, error)
	newTableIndex() tableIndex
}

// TableWritable is a constraint for objects that implement tabular
// pretty-printing. Used by the "db" script commands to render a table.
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
	reservedIndexPrefix       = "__"
	RevisionIndex             = "__revision__"
	RevisionIndexPos          = 0
	GraveyardIndex            = "__graveyard__"
	GraveyardIndexPos         = 1
	GraveyardRevisionIndex    = "__graveyard_revision__"
	GraveyardRevisionIndexPos = 2

	PrimaryIndexPos        = 3
	SecondaryIndexStartPos = 4
)

// object is the format in which data is stored in the tables.
type object struct {
	data     any
	revision uint64
}

// anyIndexer is an untyped indexer. The user-defined 'Index[Obj,Key]'
// is converted to this form.
type anyIndexer struct {
	// name is the indexer name.
	name string

	// fromObject returns the key (or keys for multi-index) to index the
	// object with.
	fromObject func(object) index.KeySet

	// fromString converts string into a key. Optional.
	fromString func(string) (index.Key, error)

	newTableIndex func() tableIndex

	// pos is the position of the index in [tableEntry.indexes]
	pos int
}

type anyDeleteTracker interface {
	setRevision(uint64)
	getRevision() uint64
	close()
}

type tableInternal interface {
	tableEntry() *tableEntry
	tablePos() int
	setTablePos(int)
	indexPos(string) int
	getIndexer(name string) *anyIndexer
	secondary() []anyIndexer               // Secondary indexers (if any)
	sortableMutex() internal.SortableMutex // The sortable mutex for locking the table for writing
	anyChanges(txn WriteTxn) (anyChangeIterator, error)
	typeName() string                       // Returns the 'Obj' type as string
	unmarshalYAML(data []byte) (any, error) // Unmarshal the data into 'Obj'
	numDeletedObjects(txn ReadTxn) int      // Number of objects in graveyard
	acquired(*writeTxnState)
	released()
	getAcquiredInfo() string
	tableHeader() []string
	tableRowAny(any) []string
}

// tableIndexIterator for iterating over keys and objects in an index.
// This is not a straight up iter.Seq2 as this way we avoid a heap allocation
// for a function closure.
type tableIndexIterator interface {
	All(yield func(key []byte, obj object) bool)
}

type tableIndexReader interface {
	len() int
	get(key index.Key) (object, <-chan struct{}, bool)
	prefix(key index.Key) (tableIndexIterator, <-chan struct{})
	lowerBound(key index.Key) (tableIndexIterator, <-chan struct{})
	lowerBoundNext(key index.Key) (func() ([]byte, object, bool), <-chan struct{})
	list(key index.Key) (tableIndexIterator, <-chan struct{})
	all() (tableIndexIterator, <-chan struct{})
	rootWatch() <-chan struct{}
	objectToKey(obj object) index.Key
}

type tableIndex interface {
	tableIndexReader
	txn() (tableIndexTxn, bool)
	commit() (idx tableIndex, txn tableIndexTxnNotify)
}

type tableIndexTxn interface {
	tableIndex

	insert(key index.Key, obj object) (old object, hadOld bool, watch <-chan struct{})
	modify(key index.Key, obj object, mod func(old, new object) object) (old object, new object, hadOld bool, watch <-chan struct{})
	delete(key index.Key) (old object, hadOld bool)
	reindex(primaryKey index.Key, old object, new object)
}

type tableIndexTxnNotify interface {
	notify()
}

type tableInitialization struct {
	// watch channel which is closed when the table becomes initialized,
	// e.g. when all [pending] initializers are marked done.
	watch chan struct{}

	// pending initializers.
	pending []string
}

// tableEntry contains the table state. The database is a slice of
// these table entries.
type tableEntry struct {
	// meta is the metadata about the table
	meta TableMeta

	// deleteTrackers are the open Changes() iterators for which
	// we set aside deleted objects.
	deleteTrackers *part.Tree[anyDeleteTracker]

	// init if not nil marks the table as not initialized.
	// When the last registered initializer is done this is
	// set to nil and the [init.watch] is closed.
	init *tableInitialization

	// indexes are the table indexes that store the objects
	indexes []tableIndex

	// revision is the current table revision. It's the same
	// as the revision of the last inserted object.
	revision uint64

	// locked marks the table locked for writes.
	locked bool
}

func (t *tableEntry) numObjects() int {
	return t.indexes[RevisionIndexPos].len()
}

func (t *tableEntry) numDeletedObjects() int {
	return t.indexes[GraveyardIndexPos].len()
}
