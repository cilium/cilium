// Copyright 2012 James Cooper. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package gorp

import (
	"context"
	"database/sql"
	"time"
)

// Transaction represents a database transaction.
// Insert/Update/Delete/Get/Exec operations will be run in the context
// of that transaction.  Transactions should be terminated with
// a call to Commit() or Rollback()
type Transaction struct {
	ctx    context.Context
	dbmap  *DbMap
	tx     *sql.Tx
	closed bool
}

func (t *Transaction) WithContext(ctx context.Context) SqlExecutor {
	copy := &Transaction{}
	*copy = *t
	copy.ctx = ctx
	return copy
}

// Insert has the same behavior as DbMap.Insert(), but runs in a transaction.
func (t *Transaction) Insert(list ...interface{}) error {
	return insert(t.dbmap, t, list...)
}

// Update had the same behavior as DbMap.Update(), but runs in a transaction.
func (t *Transaction) Update(list ...interface{}) (int64, error) {
	return update(t.dbmap, t, nil, list...)
}

// UpdateColumns had the same behavior as DbMap.UpdateColumns(), but runs in a transaction.
func (t *Transaction) UpdateColumns(filter ColumnFilter, list ...interface{}) (int64, error) {
	return update(t.dbmap, t, filter, list...)
}

// Delete has the same behavior as DbMap.Delete(), but runs in a transaction.
func (t *Transaction) Delete(list ...interface{}) (int64, error) {
	return delete(t.dbmap, t, list...)
}

// Get has the same behavior as DbMap.Get(), but runs in a transaction.
func (t *Transaction) Get(i interface{}, keys ...interface{}) (interface{}, error) {
	return get(t.dbmap, t, i, keys...)
}

// Select has the same behavior as DbMap.Select(), but runs in a transaction.
func (t *Transaction) Select(i interface{}, query string, args ...interface{}) ([]interface{}, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return hookedselect(t.dbmap, t, i, query, args...)
}

// Exec has the same behavior as DbMap.Exec(), but runs in a transaction.
func (t *Transaction) Exec(query string, args ...interface{}) (sql.Result, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, args...)
	}
	return maybeExpandNamedQueryAndExec(t, query, args...)
}

// SelectInt is a convenience wrapper around the gorp.SelectInt function.
func (t *Transaction) SelectInt(query string, args ...interface{}) (int64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectInt(t, query, args...)
}

// SelectNullInt is a convenience wrapper around the gorp.SelectNullInt function.
func (t *Transaction) SelectNullInt(query string, args ...interface{}) (sql.NullInt64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectNullInt(t, query, args...)
}

// SelectFloat is a convenience wrapper around the gorp.SelectFloat function.
func (t *Transaction) SelectFloat(query string, args ...interface{}) (float64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectFloat(t, query, args...)
}

// SelectNullFloat is a convenience wrapper around the gorp.SelectNullFloat function.
func (t *Transaction) SelectNullFloat(query string, args ...interface{}) (sql.NullFloat64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectNullFloat(t, query, args...)
}

// SelectStr is a convenience wrapper around the gorp.SelectStr function.
func (t *Transaction) SelectStr(query string, args ...interface{}) (string, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectStr(t, query, args...)
}

// SelectNullStr is a convenience wrapper around the gorp.SelectNullStr function.
func (t *Transaction) SelectNullStr(query string, args ...interface{}) (sql.NullString, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectNullStr(t, query, args...)
}

// SelectOne is a convenience wrapper around the gorp.SelectOne function.
func (t *Transaction) SelectOne(holder interface{}, query string, args ...interface{}) error {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	return SelectOne(t.dbmap, t, holder, query, args...)
}

// Commit commits the underlying database transaction.
func (t *Transaction) Commit() error {
	if !t.closed {
		t.closed = true
		if t.dbmap.logger != nil {
			now := time.Now()
			defer t.dbmap.trace(now, "commit;")
		}
		return t.tx.Commit()
	}

	return sql.ErrTxDone
}

// Rollback rolls back the underlying database transaction.
func (t *Transaction) Rollback() error {
	if !t.closed {
		t.closed = true
		if t.dbmap.logger != nil {
			now := time.Now()
			defer t.dbmap.trace(now, "rollback;")
		}
		return t.tx.Rollback()
	}

	return sql.ErrTxDone
}

// Savepoint creates a savepoint with the given name. The name is interpolated
// directly into the SQL SAVEPOINT statement, so you must sanitize it if it is
// derived from user input.
func (t *Transaction) Savepoint(name string) error {
	query := "savepoint " + t.dbmap.Dialect.QuoteField(name)
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	_, err := exec(t, query)
	return err
}

// RollbackToSavepoint rolls back to the savepoint with the given name. The
// name is interpolated directly into the SQL SAVEPOINT statement, so you must
// sanitize it if it is derived from user input.
func (t *Transaction) RollbackToSavepoint(savepoint string) error {
	query := "rollback to savepoint " + t.dbmap.Dialect.QuoteField(savepoint)
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	_, err := exec(t, query)
	return err
}

// ReleaseSavepint releases the savepoint with the given name. The name is
// interpolated directly into the SQL SAVEPOINT statement, so you must sanitize
// it if it is derived from user input.
func (t *Transaction) ReleaseSavepoint(savepoint string) error {
	query := "release savepoint " + t.dbmap.Dialect.QuoteField(savepoint)
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	_, err := exec(t, query)
	return err
}

// Prepare has the same behavior as DbMap.Prepare(), but runs in a transaction.
func (t *Transaction) Prepare(query string) (*sql.Stmt, error) {
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	return prepare(t, query)
}

func (t *Transaction) QueryRow(query string, args ...interface{}) *sql.Row {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, args...)
	}
	return queryRow(t, query, args...)
}

func (t *Transaction) Query(q string, args ...interface{}) (*sql.Rows, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&q, args...)
	}

	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, q, args...)
	}
	return query(t, q, args...)
}
