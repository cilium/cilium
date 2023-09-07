// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"errors"
	"fmt"
)

var (
	// ErrDuplicateTable indicates that StateDB has been provided with two or more table definitions
	// that share the same table name.
	ErrDuplicateTable = errors.New("table already exists")

	// ErrPrimaryIndexNotUnique indicates that the primary index for the table is not marked unique.
	ErrPrimaryIndexNotUnique = errors.New("primary index not unique")

	// ErrDuplicateIndex indicates that the table has two or more indexers that share the same name.
	ErrDuplicateIndex = errors.New("index name already in use")

	// ErrReservedPrefix indicates that the index name is using the reserved prefix and should
	// be renamed.
	ErrReservedPrefix = errors.New("index name uses reserved prefix '" + reservedIndexPrefix + "'")

	// ErrTransactionClosed indicates that a write operation is performed using a transaction
	// that has already been committed or aborted.
	ErrTransactionClosed = errors.New("transaction is closed")

	// ErrTableNotLockedForWriting indicates that a write operation is performed against a
	// table that was not locked for writing, e.g. target table not given as argument to
	// WriteTxn().
	ErrTableNotLockedForWriting = errors.New("not locked for writing")
)

// tableError wraps an error with the table name.
func tableError(tableName string, err error) error {
	return fmt.Errorf("table %q: %w", tableName, err)
}
