// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"encoding/json"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"

	"github.com/cilium/cilium/pkg/stream"
)

func New(p params) (DB, error) {
	dbSchema := &memdb.DBSchema{
		Tables: make(map[string]*memdb.TableSchema),
	}
	for _, tableSchema := range p.Schemas {
		if _, ok := dbSchema.Tables[tableSchema.Name]; ok {
			panic(fmt.Sprintf("Table %q already registered", tableSchema.Name))
		}
		dbSchema.Tables[tableSchema.Name] = tableSchema
	}
	memdb, err := memdb.NewMemDB(dbSchema)
	if err != nil {
		return nil, err
	}
	db := &stateDB{
		memDB:    memdb,
		revision: 0,
	}
	db.Observable, db.emit, _ = stream.Multicast[Event]()

	return db, nil
}

// stateDB implements StateDB using go-memdb.
type stateDB struct {
	stream.Observable[Event]
	emit func(Event)

	memDB    *memdb.MemDB
	revision uint64 // Commit revision, protected by the write tx lock.
}

var _ DB = &stateDB{}

// ToJSON marshals the whole database into a JSON string.
func (db *stateDB) ToJSON() ([]byte, error) {
	tx := db.memDB.Txn(false)
	out := map[string][]any{}
	for table := range db.memDB.DBSchema().Tables {
		iter, err := tx.Get(table, "id")
		if err != nil {
			panic(err)
		}
		objs := []any{}
		for obj := iter.Next(); obj != nil; obj = iter.Next() {
			objs = append(objs, obj)
		}
		out[table] = objs
	}
	return json.Marshal(out)
}

// WriteTxn constructs a new WriteTransaction
func (db *stateDB) WriteTxn() WriteTransaction {
	txn := db.memDB.Txn(true)
	txn.TrackChanges()
	return &transaction{
		db:  db,
		txn: txn,
		// Assign a revision to the transaction. Protected by
		// the memDB writer lock that we acquired with Txn(true).
		revision: db.revision + 1,
	}
}

// ReadTxn constructs a new ReadTransaction.
func (db *stateDB) ReadTxn() ReadTransaction {
	return &transaction{db: nil, txn: db.memDB.Txn(false)}
}

// transaction implements ReadTransaction and WriteTransaction using go-memdb.
type transaction struct {
	db       *stateDB
	revision uint64
	txn      *memdb.Txn
}

func (t *transaction) getTxn() *memdb.Txn { return t.txn }
func (t *transaction) Revision() uint64   { return t.revision }
func (t *transaction) Abort()             { t.txn.Abort() }
func (t *transaction) Defer(fn func())    { t.txn.Defer(fn) }

func (t *transaction) Commit() error {
	changedTables := map[string]struct{}{}
	for _, change := range t.txn.Changes() {
		changedTables[change.Table] = struct{}{}
	}
	t.db.revision = t.revision
	t.txn.Commit()

	// Notify that these tables have changed. We are not concerned
	// about the order in which these events are received by subscribers.
	for table := range changedTables {
		t.db.emit(Event{Table: TableName(table)})
	}
	return nil
}
