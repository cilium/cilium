// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"errors"
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

	// List returns sequence of objects matching the given query.
	List(ReadTxn, Query[Obj]) iter.Seq2[Obj, Revision]

	// ListWatch returns an iterator for all objects matching the given query
	// and a watch channel that is closed if the query results are
	// invalidated by a write to the table.
	ListWatch(ReadTxn, Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{})

	// Get returns the first matching object for the query.
	Get(ReadTxn, Query[Obj]) (obj Obj, rev Revision, found bool)

	// GetWatch return the first matching object and a watch channel
	// that is closed if the query is invalidated.
	GetWatch(ReadTxn, Query[Obj]) (obj Obj, rev Revision, watch <-chan struct{}, found bool)

	// LowerBound returns an iterator for objects that have a key
	// greater or equal to the query.
	LowerBound(ReadTxn, Query[Obj]) iter.Seq2[Obj, Revision]

	// LowerBoundWatch returns an iterator for objects that have a key
	// greater or equal to the query. The returned watch channel is closed
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
	Changes(WriteTxn) (ChangeIterator[Obj], error)
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
	// If the transaction given to Next is a WriteTxn the modifications made in the
	// transaction are not observed, that is, only committed changes can be observed.
	Next(ReadTxn) (iter.Seq2[Change[Obj], Revision], <-chan struct{})
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

	// InsertWatch an object into the table. Returns the object that was
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

type tableInternal interface {
	tableEntry() tableEntry
	tablePos() int
	setTablePos(int)
	indexPos(string) int
	tableKey() []byte // The radix key for the table in the root tree
	getIndexer(name string) *anyIndexer
	primary() anyIndexer                   // The untyped primary indexer for the table
	secondary() map[string]anyIndexer      // Secondary indexers (if any)
	sortableMutex() internal.SortableMutex // The sortable mutex for locking the table for writing
	anyChanges(txn WriteTxn) (anyChangeIterator, error)
	proto() any                             // Returns the zero value of 'Obj', e.g. the prototype
	unmarshalYAML(data []byte) (any, error) // Unmarshal the data into 'Obj'
	numDeletedObjects(txn ReadTxn) int      // Number of objects in graveyard
	acquired(*txn)
	getAcquiredInfo() string
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
	// Name of the index
	Name string

	// FromObject extracts key(s) from the object. The key set
	// can contain 0, 1 or more keys.
	FromObject func(obj Obj) index.KeySet

	// FromKey converts the index key into a raw key.
	// With this we can perform Query() against this index with
	// the [Key] type.
	FromKey func(key Key) index.Key

	// FromString is an optional conversion from string to a raw key.
	// If implemented allows script commands to query with this index.
	FromString func(key string) (index.Key, error)

	// Unique marks the index as unique. Primary index must always be
	// unique. A secondary index may be non-unique in which case a single
	// key may map to multiple objects.
	Unique bool
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

var errFromStringNil = errors.New("FromString not defined")

//nolint:unused
func (i Index[Obj, Key]) fromString(s string) (index.Key, error) {
	if i.FromString == nil {
		return index.Key{}, errFromStringNil
	}
	k, err := i.FromString(s)
	k = i.encodeKey(k)
	return k, err
}

//nolint:unused
func (i Index[Obj, Key]) isUnique() bool {
	return i.Unique
}

func (i Index[Obj, Key]) encodeKey(key []byte) []byte {
	if !i.Unique {
		return encodeNonUniqueBytes(key)
	}
	return key
}

// Query constructs a query against this index from a key.
func (i Index[Obj, Key]) Query(key Key) Query[Obj] {
	return Query[Obj]{
		index: i.Name,
		key:   i.encodeKey(i.FromKey(key)),
	}
}

func (i Index[Obj, Key]) QueryFromObject(obj Obj) Query[Obj] {
	return Query[Obj]{
		index: i.Name,
		key:   i.encodeKey(i.FromObject(obj).First()),
	}
}

func (i Index[Obj, Key]) ObjectToKey(obj Obj) index.Key {
	return i.encodeKey(i.FromObject(obj).First())
}

// Indexer is the "FromObject" subset of Index[Obj, Key]
// without the 'Key' constraint.
type Indexer[Obj any] interface {
	indexName() string
	isUnique() bool
	fromObject(Obj) index.KeySet
	fromString(string) (index.Key, error)

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

	// fromString converts string into a key. Optional.
	fromString func(string) (index.Key, error)

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
	initialized         bool
	initWatchChan       chan struct{}
}

func (t *tableEntry) numObjects() int {
	indexEntry := t.indexes[t.meta.indexPos(RevisionIndex)]
	if indexEntry.txn != nil {
		return indexEntry.txn.Len()
	}
	return indexEntry.tree.Len()
}

func (t *tableEntry) numDeletedObjects() int {
	indexEntry := t.indexes[t.meta.indexPos(GraveyardIndex)]
	if indexEntry.txn != nil {
		return indexEntry.txn.Len()
	}
	return indexEntry.tree.Len()
}
