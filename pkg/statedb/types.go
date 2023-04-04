// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"io"

	memdb "github.com/hashicorp/go-memdb"

	"github.com/cilium/cilium/pkg/stream"
)

type DB interface {
	// Observable for observing when tables in the state are changed.
	// It is preferred to use more fine-grained notifications via
	// WatchableIterator when possible.
	//
	// The events may not follow a strict ordering, e.g. if write transactions
	// are performed to table A and then to table B, the observer may see event
	// for table B before table A. Thus these events should only be used as
	// (throttled) triggers to schedule reconciling work.
	stream.Observable[Event]

	// WriteJSON marshals out the whole database as JSON into the given writer.
	WriteJSON(io.Writer) error

	// ReadTxn constructs a new read transaction that can be used to read tables.
	// Reads occur against a snapshot of the database at the time of the call and
	// do not block other readers or writers. A new read transaction is needed to observe
	// new changes to the database.
	ReadTxn() ReadTransaction

	// WriteTxn constructs a new write transaction that can be used
	// to modify tables. Caller must call Commit() or Abort() to release
	// the database write lock.
	WriteTxn() WriteTransaction
}

type Event struct {
	Table TableName // The name of the table that changed
}

// TableName is an opaque type carrying the name a table. Returned by Table[T].Name().
type TableName string

// WatchableIterator is an Iterator that provides notification
// when the iterator results have been invalidated by a change
// in the database.
type WatchableIterator[Obj any] interface {
	Iterator[Obj]

	// Invalidated returns a channel that is closed when the results
	// returned by the iterator have changed in the database.
	Invalidated() <-chan struct{}
}

// Iterator for a set of items.
type Iterator[Obj any] interface {
	// Next returns the next object and true, or zero value and false if iteration
	// has finished.
	Next() (Obj, bool)
}

// WriteTransaction can be used with one more 'Table's to make a set of atomic
// changes to them.
type WriteTransaction interface {
	getTxn() *memdb.Txn

	// Abort the transaction and throw away the changes.
	Abort()

	// Commit the transaction to the database. May fail if a commit hook
	// fails. On failure the changes are discarded and caller should retry
	// at a later point in time.
	Commit() error

	// Revision of the database. Revision is a simple counter of committed
	// transactions and can be used within the objects for detecting which
	// objects has changed.
	Revision() uint64

	// Defer registers a function to run after the transaction has been
	// successfully committed.
	Defer(fn func())
}

// ReadTransaction can be used to read data in tables. It provides a consistent
// snapshot of the database across all tables.
type ReadTransaction interface {
	getTxn() *memdb.Txn
}

// ObjectConstraints specifies the constraints that an object
// must fulfill for it to be stored in a table.
type ObjectConstraints[Obj any] interface {
	DeepCopy() Obj
}

// Table provides read and write access to a specific table.
type Table[Obj ObjectConstraints[Obj]] interface {
	Name() TableName

	// Reader when given a read transaction returns a table reader
	// that can be used to read from the snapshot of the database.
	Reader(tx ReadTransaction) TableReader[Obj]

	// Writer when given a write transaction returns a table writer
	// that can be used to modify the table.
	Writer(tx WriteTransaction) TableReaderWriter[Obj]
}

// TableReader provides a set of read-only queries to a table.
//
// It is encouraged to wrap these methods behind a table-specific API as these
// methods may fail if query is badly formed. E.g. wrap Get(ByName(...) into
// GetByName that constructs the query and panics on errors (since those are
// indication of the method or table schema being broken).
//
// Objects returned by these methods are considered immutable and MUST never be mutated
// by the caller! To modify an object for insertion, it MUST be DeepCopy()'d first.
type TableReader[Obj ObjectConstraints[Obj]] interface {
	// First returns the first matching object with the given query. Returned
	// object is nil if the object does not exist. Error is non-nil if the query
	// is malformed (e.g. unknown index).
	First(Query) (Obj, error)

	// Last returns the last matching object with the given query. Returned
	// object is nil if the object does not exist. Error is non-nil if the query
	// is malformed (e.g. unknown index).
	Last(Query) (Obj, error)

	// Get returns all objects matching the given query as a WatchableIterator
	// that allows iterating over the set of matching objects and to watch whether
	// the query has been invalidated by changes to the database. Returns
	// an error if the query is malformed.
	Get(Query) (WatchableIterator[Obj], error)

	// LowerBound returns objects that are equal to or higher than the query. The
	// comparison is performed against byte slices derived from the index argument(s).
	LowerBound(Query) (Iterator[Obj], error)
}

// TableReaderWriter provides methods to modify a table.
//
// It is encouraged to wrap these methods behind a safer table-specific API as these
// expose errors related to malformed indices that the user of the table should not need
// to handle.
type TableReaderWriter[Obj ObjectConstraints[Obj]] interface {
	TableReader[Obj]

	// Insert an object into the table. May return an error if indexing fails.
	Insert(obj Obj) error

	// Delete an object from the table. May return an error if the "id" index key
	// cannot be computed.
	Delete(obj Obj) error

	// DeleteAll deletes all matching objects from the table. May return an error
	// on indexing issues.
	DeleteAll(Query) (n int, err error)
}

// Index is an opaque type pointing to a specific index on a table. Indexes
// are defined alongside the table schema.
type Index string

// Query against a table using a specific index and argument(s). Queries
// should be predefined with strong typing alongside the table schema
// definition.
type Query struct {
	Index Index // The table index to query against
	Args  []any // The query argument(s).
}
