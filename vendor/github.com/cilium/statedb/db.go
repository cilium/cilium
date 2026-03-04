// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/statedb/internal"
)

// DB provides an in-memory transaction database built on top of immutable radix
// trees. The database supports multiple tables, each with one or more user-defined
// indexes. Readers can access the data locklessly with a simple atomic pointer read
// to obtain a snapshot. On writes to the database table-level locks are acquired
// on target tables and on write transaction commit a root lock is taken to swap
// in the new root with the modified tables.
//
// As data is stored in immutable data structures any objects inserted into
// it MUST NOT be mutated afterwards.
//
// DB holds the "root" tree of tables with each table holding a tree of indexes:
//
//	           root
//	          /    \
//	         ba    T(foo)
//	       /   \
//	   T(bar)  T(baz)
//
//	      T(bar).indexes
//		   /  \
//		  i    I(byRevision)
//		/   \
//	   I(id)    I(ip)
//
//	          I(ip)
//	          /  \
//	        192  172
//	        /     ...
//	    bar(192.168.1.1)
//
// T = tableEntry
// I = indexTree
//
// To lookup:
//  1. Create a read (or write) transaction
//  2. Find the table from the root tree
//  3. Find the index from the table's index tree
//  4. Find the object from the index
//
// To insert:
//  1. Create write transaction against the target table
//  2. Find the table from the root tree
//  3. Create/reuse write transaction on primary index
//  4. Insert/replace the object into primary index
//  5. Create/reuse write transaction on revision index
//  6. If old object existed, remove from revision index
//  7. If old object existed, remove from graveyard
//  8. Update each secondary index
//  9. Commit transaction by committing each index to
//     the table and then committing table to the root.
//     Swap the root atomic pointer to new root and
//     notify by closing channels of all modified nodes.
//
// To observe deletions:
//  1. Create write transaction against the target table
//  2. Create new delete tracker and add it to the table
//  3. Commit the write transaction to update the table
//     with the new delete tracker
//  4. Query the graveyard by revision, starting from the
//     revision of the write transaction at which it was
//     created.
//  5. For each successfully processed deletion, mark the
//     revision to set low watermark for garbage collection.
//  6. Periodically garbage collect the graveyard by finding
//     the lowest revision of all delete trackers.
type DB struct {
	handleName string
	*dbState
}

// dbState is the underlying state of the database shared by all [DB] handles.
type dbState struct {
	mu                  sync.Mutex // protects 'tables' and sequences modifications to the root tree
	ctx                 context.Context
	cancel              context.CancelFunc
	root                atomic.Pointer[dbRoot]
	gcTrigger           chan struct{} // trigger for graveyard garbage collection
	gcExited            chan struct{}
	gcRateLimitInterval time.Duration
	metrics             Metrics
	writeTxnPool        sync.Pool
}

type dbRoot = []*tableEntry

type Option func(*opts)

type opts struct {
	metrics Metrics
}

func WithMetrics(m Metrics) Option {
	return func(o *opts) {
		o.metrics = m
	}
}

// New creates a new database.
//
// The created database must be started and stopped!
func New(options ...Option) *DB {
	var opts opts
	for _, o := range options {
		o(&opts)
	}
	if opts.metrics == nil {
		// Use the default metrics implementation but don't publish it.
		opts.metrics = NewExpVarMetrics(false)
	}

	db := &DB{
		dbState: &dbState{
			metrics:             opts.metrics,
			gcRateLimitInterval: defaultGCRateLimitInterval,
		},
	}
	db.updateWriteTxnPoolLocked(0)
	db.handleName = "DB"
	root := dbRoot{}
	db.root.Store(&root)
	return db
}

func (db *DB) updateWriteTxnPoolLocked(numTables int) {
	const defaultNumTables = 4
	db.writeTxnPool.New =
		func() any {
			return &writeTxnState{
				db:           db,
				tableEntries: make([]*tableEntry, 0, numTables),
				smus:         make(internal.SortableMutexes, 0, defaultNumTables),
				tableNames:   make([]string, 0, defaultNumTables),
			}
		}
}

func (db *DB) registerTable(table TableMeta) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	root := slices.Clone(*db.root.Load())

	name := table.Name()
	for _, t := range root {
		if t.meta.Name() == name {
			return tableError(name, ErrDuplicateTable)
		}
	}

	pos := len(root)
	table.setTablePos(pos)
	root = append(root, table.tableEntry())

	db.updateWriteTxnPoolLocked(len(root))

	db.root.Store(&root)
	return nil
}

// ReadTxn constructs a new read transaction for performing reads against
// a snapshot of the database.
//
// The returned ReadTxn is not thread-safe.
func (db *DB) ReadTxn() ReadTxn {
	return (*readTxn)(db.root.Load())
}

// WriteTxn constructs a new write transaction against the given set of tables.
// Each table is locked, which may block until the table locks are acquired.
// The modifications performed in the write transaction are not visible outside
// it until Commit() is called. To discard the changes call Abort().
//
// The returned WriteTxn is not thread-safe.
func (db *DB) WriteTxn(tables ...TableMeta) WriteTxn {
	txn := db.writeTxnPool.Get().(*writeTxnState)
	txn.db = db

	txn.smus = reuseSlice(txn.smus, len(tables))
	for i, table := range tables {
		txn.smus[i] = table.sortableMutex()
		if table.tablePos() < 0 {
			panic(tableError(table.Name(), ErrTableNotRegistered))
		}
	}

	lockAt := time.Now()
	txn.smus.Lock()
	acquiredAt := time.Now()

	txn.tableEntries = slices.Clone(*db.root.Load())
	txn.handle = db.handleName
	txn.acquiredAt = acquiredAt

	txn.tableNames = reuseSlice(txn.tableNames, len(tables))
	for i, table := range tables {
		pos := table.tablePos()
		tableEntryCopy := *txn.tableEntries[pos]
		tableEntryCopy.indexes = slices.Clone(tableEntryCopy.indexes)
		tableEntryCopy.locked = true
		txn.tableEntries[pos] = &tableEntryCopy
		name := table.Name()
		txn.tableNames[i] = name

		db.metrics.WriteTxnTableAcquisition(
			db.handleName,
			name,
			table.sortableMutex().AcquireDuration(),
		)
		table.acquired(txn)
	}

	// Sort the table names so they always appear ordered in metrics.
	sort.Strings(txn.tableNames)
	db.metrics.WriteTxnTotalAcquisition(
		db.handleName,
		txn.tableNames,
		acquiredAt.Sub(lockAt),
	)

	handle := &writeTxnHandle{txn, nil}
	runtime.SetFinalizer(handle, txnFinalizer)
	return handle
}

func (db *DB) GetTables(txn ReadTxn) (tbls []TableMeta) {
	root := txn.root()
	tbls = make([]TableMeta, 0, len(root))
	for _, table := range root {
		tbls = append(tbls, table.meta)
	}
	return
}

func (db *DB) GetTable(txn ReadTxn, name string) TableMeta {
	root := txn.root()
	for _, table := range root {
		if table.meta.Name() == name {
			return table.meta
		}
	}
	return nil
}

// Start the background workers for the database.
//
// This starts the graveyard worker that deals with garbage collecting
// deleted objects that are no longer necessary for Changes().
func (db *DB) Start() error {
	db.gcTrigger = make(chan struct{}, 1)
	db.gcExited = make(chan struct{})
	db.ctx, db.cancel = context.WithCancel(context.Background())
	go graveyardWorker(db, db.ctx, db.gcRateLimitInterval)
	return nil
}

// Stop the background workers.
func (db *DB) Stop() error {
	db.cancel()
	<-db.gcExited
	return nil
}

// ServeHTTP is an HTTP handler for dumping StateDB as JSON.
//
// Example usage:
//
//	var db *statedb.DB
//
//	http.Handle("/db", db)
//	http.ListenAndServe(":8080", nil)
func (db *DB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	db.ReadTxn().WriteJSON(w)
}

// setGCRateLimitInterval can set the graveyard GC interval before DB is started.
// Used by tests.
func (db *DB) setGCRateLimitInterval(interval time.Duration) {
	db.gcRateLimitInterval = interval
}

// NewHandle returns a new named handle to the DB. The given name is used to annotate
// metrics.
func (db *DB) NewHandle(name string) *DB {
	return &DB{
		handleName: name,
		dbState:    db.dbState,
	}
}

func reuseSlice[T any](s []T, length int) []T {
	if cap(s) < length {
		return make([]T, length)
	}
	s = s[:length]
	return s
}
