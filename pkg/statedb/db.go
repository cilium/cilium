// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
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
	mu                  lock.Mutex // protects 'tables' and sequences modifications to the root tree
	tables              map[TableName]TableMeta
	ctx                 context.Context
	cancel              context.CancelFunc
	root                atomic.Pointer[iradix.Tree[tableEntry]]
	gcTrigger           chan struct{} // trigger for graveyard garbage collection
	gcExited            chan struct{}
	gcRateLimitInterval time.Duration
	metrics             Metrics
}

func NewDB(tables []TableMeta, metrics Metrics) (*DB, error) {
	txn := iradix.New[tableEntry]().Txn()
	db := &DB{
		tables:              make(map[TableName]TableMeta),
		metrics:             metrics,
		gcRateLimitInterval: defaultGCRateLimitInterval,
	}
	for _, t := range tables {
		if err := db.registerTable(t, txn); err != nil {
			return nil, err
		}
	}
	db.root.Store(txn.CommitOnly())

	return db, nil
}

// RegisterTable registers a table to the database:
//
//	func NewMyTable() statedb.RWTable[MyTable] { ... }
//	cell.Provide(NewMyTable),
//	cell.Invoke(statedb.RegisterTable[MyTable]),
func RegisterTable[Obj any](db *DB, table RWTable[Obj]) error {
	return db.RegisterTable(table)
}

// RegisterTable registers a table to the database.
func (db *DB) RegisterTable(table TableMeta, tables ...TableMeta) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	txn := db.root.Load().Txn()
	if err := db.registerTable(table, txn); err != nil {
		return err
	}
	for _, t := range tables {
		if err := db.registerTable(t, txn); err != nil {
			return err
		}
	}
	db.root.Store(txn.CommitOnly())
	return nil
}

func (db *DB) registerTable(table TableMeta, txn *iradix.Txn[tableEntry]) error {
	name := table.Name()
	if _, ok := db.tables[name]; ok {
		return tableError(name, ErrDuplicateTable)
	}
	db.tables[name] = table
	var entry tableEntry
	entry.meta = table
	entry.deleteTrackers = iradix.New[deleteTracker]()
	indexTxn := iradix.New[indexEntry]().Txn()
	indexTxn.Insert([]byte(table.primary().name), indexEntry{iradix.New[object](), true})
	indexTxn.Insert([]byte(RevisionIndex), indexEntry{iradix.New[object](), true})
	indexTxn.Insert([]byte(GraveyardIndex), indexEntry{iradix.New[object](), true})
	indexTxn.Insert([]byte(GraveyardRevisionIndex), indexEntry{iradix.New[object](), true})
	for index, indexer := range table.secondary() {
		indexTxn.Insert([]byte(index), indexEntry{iradix.New[object](), indexer.unique})
	}
	entry.indexes = indexTxn.CommitOnly()
	txn.Insert(table.tableKey(), entry)
	return nil
}

// ReadTxn constructs a new read transaction for performing reads against
// a snapshot of the database.
//
// ReadTxn is not thread-safe!
func (db *DB) ReadTxn() ReadTxn {
	return &txn{
		db:          db,
		rootReadTxn: db.root.Load().Txn(),
	}
}

// WriteTxn constructs a new write transaction against the given set of tables.
// Each table is locked, which may block until the table locks are acquired.
// The modifications performed in the write transaction are not visible outside
// it until Commit() is called. To discard the changes call Abort().
//
// WriteTxn is not thread-safe!
func (db *DB) WriteTxn(table TableMeta, tables ...TableMeta) WriteTxn {
	callerPkg := callerPackage()

	allTables := append(tables, table)
	smus := lock.SortableMutexes{}
	for _, table := range allTables {
		smus = append(smus, table.sortableMutex())
	}
	lockAt := time.Now()
	smus.Lock()
	acquiredAt := time.Now()

	rootReadTxn := db.root.Load().Txn()
	tableEntries := make(map[TableName]*tableEntry, len(tables))
	var tableNames []string
	for _, table := range allTables {
		tableEntry, ok := rootReadTxn.Get(table.tableKey())
		if !ok {
			panic("BUG: Table '" + table.Name() + "' not found")
		}
		tableEntries[table.Name()] = &tableEntry
		tableNames = append(tableNames, table.Name())

		db.metrics.TableContention.With(prometheus.Labels{
			"table": table.Name(),
		}).Set(table.sortableMutex().AcquireDuration().Seconds())
	}

	db.metrics.WriteTxnAcquisition.With(prometheus.Labels{
		"package": callerPkg,
		"tables":  strings.Join(tableNames, "+"),
	}).Observe(acquiredAt.Sub(lockAt).Seconds())

	return &txn{
		db:             db,
		rootReadTxn:    rootReadTxn,
		modifiedTables: tableEntries,
		writeTxns:      make(map[tableIndex]indexTxn),
		smus:           smus,
		acquiredAt:     acquiredAt,
		tableNames:     strings.Join(tableNames, "+"),
		packageName:    callerPkg,
	}
}

func (db *DB) Start(cell.HookContext) error {
	db.gcTrigger = make(chan struct{}, 1)
	db.gcExited = make(chan struct{})
	db.ctx, db.cancel = context.WithCancel(context.Background())
	go graveyardWorker(db, db.ctx, db.gcRateLimitInterval)
	return nil
}

func (db *DB) Stop(stopCtx cell.HookContext) error {
	db.cancel()
	select {
	case <-stopCtx.Done():
		return errors.New("timed out waiting for graveyard worker to exit")
	case <-db.gcExited:
	}
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

var ciliumPackagePrefix = func() string {
	sentinel := func() {}
	name := runtime.FuncForPC(reflect.ValueOf(sentinel).Pointer()).Name()
	if idx := strings.Index(name, "pkg/"); idx >= 0 {
		return name[:idx]
	}
	return ""
}()

func callerPackage() string {
	var callerPkg string
	pc, _, _, ok := runtime.Caller(2)
	if ok {
		f := runtime.FuncForPC(pc)
		if f != nil {
			callerPkg = f.Name()
			callerPkg, _ = strings.CutPrefix(callerPkg, ciliumPackagePrefix)
			callerPkg = strings.SplitN(callerPkg, ".", 2)[0]
		} else {
			callerPkg = "unknown"
		}
	} else {
		callerPkg = "unknown"
	}
	return callerPkg
}
