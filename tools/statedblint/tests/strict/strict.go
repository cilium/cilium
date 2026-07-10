// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package strict tests that Changes().Close() is called.
// nolint:all // ignore all lints on purpose
package strict

import "github.com/cilium/statedb"

func leakedChangeIterator(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	iter, _ := foo.Changes(wtxn)
	wtxn.Commit()
	_ = iter
} // want `change iterator "iter" is not closed on all paths; call Close\(\) or defer iter.Close\(\)`

func leakedChangeIteratorOnReturn(db *statedb.DB, foo statedb.RWTable[int]) error {
	wtxn := db.WriteTxn(foo)
	iter, _ := foo.Changes(wtxn)
	wtxn.Commit()
	_ = iter
	return nil // want `change iterator "iter" is not closed on all paths; call Close\(\) or defer iter.Close\(\)`
}

func overwrittenChangeIterator(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	iter, _ := foo.Changes(wtxn)
	wtxn.Commit()

	wtxn = db.WriteTxn(foo)
	iter, _ = foo.Changes(wtxn) // want `change iterator "iter" is overwritten without Close\(\)`
	wtxn.Commit()
	iter.Close()
}

func okDeferIteratorClose(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	iter, _ := foo.Changes(wtxn)
	wtxn.Commit()
	defer iter.Close()
}
