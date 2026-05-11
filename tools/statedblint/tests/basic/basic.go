// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package basic tests the default features of the linter
// nolint:all // ignore all lints on purpose
package basic

import (
	"sync/atomic"

	"github.com/cilium/statedb"
)

type ptrObj struct {
	Value int
}

type valueObj struct {
	Value int
}

func wrongTable(db *statedb.DB, foo, bar statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	defer wtxn.Abort()
	foo.Insert(wtxn, 1)
	bar.Insert(wtxn, 1) // want `write transaction "wtxn" does not lock table bar`
}

func wrongTableAfterBranch(db *statedb.DB, foo, bar statedb.RWTable[int], cond bool) {
	wtxn := db.WriteTxn(foo)
	defer wtxn.Abort()
	if cond {
		_ = cond
	}
	bar.Insert(wtxn, 1) // want `write transaction "wtxn" does not lock table bar`
}

func okInitializerNotUnused(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	init := foo.RegisterInitializer(wtxn, "foo")
	wtxn.Commit()

	wtxn = db.WriteTxn(foo)
	init(wtxn)
	wtxn.Commit()
}

func useAfterCommit(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	wtxn.Commit()
	foo.Insert(wtxn, 1) // want `transaction "wtxn" used after Commit\(\)`
}

func useAfterConditionalCommit(db *statedb.DB, foo statedb.RWTable[int], cond bool) {
	wtxn := db.WriteTxn(foo)
	if cond {
		wtxn.Commit()
	}
	foo.Insert(wtxn, 1) // want `transaction "wtxn" used after Commit\(\)`
	wtxn.Abort()
}

func mixedTransactions(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	foo.Insert(wtxn, 1)
	defer wtxn.Abort()
	rtxn := db.ReadTxn()                // want `opening ReadTxn while transaction "wtxn" is still live; use only one live transaction at a time`
	foo.Get(rtxn, statedb.Query[int]{}) // want `read from table foo using db.ReadTxn\(\) while write transaction "wtxn" for the same table is still open`
	_ = wtxn
}

func goroutineCapture(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	defer wtxn.Abort()
	go func() {
		foo.Insert(wtxn, 1) // want `transaction "wtxn" passed to or captured by a goroutine; StateDB transactions are not thread-safe`
	}()
}

func okNextWithWriteTxn(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	defer wtxn.Abort()
	iter, _ := foo.Changes(wtxn)
	defer iter.Close()
	iter.Next(wtxn)
}

func committedSnapshot(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	rtxn := wtxn.Commit()
	foo.Get(rtxn, statedb.Query[int]{})
}

func mixedSnapshotsOlderRead(db *statedb.DB, foo statedb.RWTable[int]) {
	rtxn := db.ReadTxn()
	wtxn := db.WriteTxn(foo) // want `opening WriteTxn while transaction "rtxn" is still live; use only one live transaction at a time`
	foo.Insert(wtxn, 1)
	defer wtxn.Abort()
	foo.NumObjects(rtxn) // want `read from table foo using db.ReadTxn\(\) while write transaction "wtxn" for the same table is still open`
	_ = wtxn
}

func leakedWriteTxn(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	foo.Insert(wtxn, 1)
} // want `write transaction "wtxn" is not closed on all paths; call Commit\(\), Abort\(\), or defer one of them`

func leakedWriteTxnInBranch(db *statedb.DB, foo statedb.RWTable[int], cond bool) {
	if cond {
		wtxn := db.WriteTxn(foo)
		foo.Insert(wtxn, 1)
	}
} // want `write transaction "wtxn" is not closed on all paths; call Commit\(\), Abort\(\), or defer one of them`

func leakedWriteTxnOnReturn(db *statedb.DB, foo statedb.RWTable[int]) error {
	wtxn := db.WriteTxn(foo)
	foo.Insert(wtxn, 1)
	return nil // want `write transaction "wtxn" is not closed on all paths; call Commit\(\), Abort\(\), or defer one of them`
}

func overwrittenWriteTxn(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	wtxn = db.WriteTxn(foo) // want `write transaction "wtxn" is overwritten without Commit\(\) or Abort\(\)`
	wtxn.Abort()
}

func okDeferAbort(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	defer wtxn.Abort()
	foo.Insert(wtxn, 1)
}

func immutablePointerGet(db *statedb.DB, foo statedb.Table[*ptrObj]) {
	txn := db.ReadTxn()
	obj, _, _ := foo.Get(txn, statedb.Query[*ptrObj]{})
	obj.Value = 1 // want `immutable pointer object "obj" returned from StateDB is mutated; clone before modifying`
}

func immutablePointerAlias(db *statedb.DB, foo statedb.Table[*ptrObj]) {
	txn := db.ReadTxn()
	obj, _, _ := foo.Get(txn, statedb.Query[*ptrObj]{})
	alias := obj
	alias.Value++ // want `immutable pointer object "alias" returned from StateDB is mutated; clone before modifying`
}

func immutablePointerRange(db *statedb.DB, foo statedb.Table[*ptrObj]) {
	txn := db.ReadTxn()
	for obj := range foo.All(txn) {
		obj.Value = 1 // want `immutable pointer object "obj" returned from StateDB is mutated; clone before modifying`
	}
}

func immutablePointerChangeObject(db *statedb.DB, foo statedb.Table[*ptrObj]) {
	wtxn := db.WriteTxn(foo)
	iter, _ := foo.Changes(wtxn)
	txn := wtxn.Commit()
	changes, _ := iter.Next(txn)
	for change := range changes {
		change.Object.Value = 1 // want `immutable pointer object "change\.Object" returned from StateDB is mutated; clone before modifying`
	}
}

func immutablePointerChangeAlias(db *statedb.DB, foo statedb.Table[*ptrObj]) {
	wtxn := db.WriteTxn(foo)
	iter, _ := foo.Changes(wtxn)
	txn := wtxn.Commit()
	changes, _ := iter.Next(txn)
	for change := range changes {
		obj := change.Object
		obj.Value = 1 // want `immutable pointer object "obj" returned from StateDB is mutated; clone before modifying`
	}
}

func okImmutableClone(db *statedb.DB, foo statedb.Table[*ptrObj]) {
	txn := db.ReadTxn()
	obj, _, _ := foo.Get(txn, statedb.Query[*ptrObj]{})
	clone := *obj
	clone.Value = 1
}

func okValueObject(db *statedb.DB, foo statedb.Table[valueObj]) {
	txn := db.ReadTxn()
	obj, _, _ := foo.Get(txn, statedb.Query[valueObj]{})
	obj.Value = 1
}

func readAfterRead(db *statedb.DB) {
	rtxn1 := db.ReadTxn()
	rtxn2 := db.ReadTxn() // want `opening ReadTxn while transaction "rtxn1" is still live; use only one live transaction at a time`
	_, _ = rtxn1, rtxn2
}

func readAfterWrite(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	defer wtxn.Abort()
	foo.Insert(wtxn, 1)
	rtxn := db.ReadTxn() // want `opening ReadTxn while transaction "wtxn" is still live; use only one live transaction at a time`
	_, _ = wtxn, rtxn
}

func writeAfterRead(db *statedb.DB, foo statedb.RWTable[int]) {
	rtxn := db.ReadTxn()
	wtxn := db.WriteTxn(foo) // want `opening WriteTxn while transaction "rtxn" is still live; use only one live transaction at a time`
	foo.Insert(wtxn, 1)
	defer wtxn.Abort()
	_, _ = rtxn, wtxn
}

func okWriteAfterDeadRead(db *statedb.DB, foo statedb.RWTable[int]) {
	rtxn := db.ReadTxn()
	_ = rtxn
	wtxn := db.WriteTxn(foo)
	foo.Insert(wtxn, 1)
	wtxn.Commit()
}

func okRefreshReadTxn(db *statedb.DB) {
	txn := db.ReadTxn()
	_ = txn
	txn = db.ReadTxn()
	_ = txn
}

func okAfterCommit(db *statedb.DB, foo statedb.RWTable[int]) {
	wtxn := db.WriteTxn(foo)
	foo.Insert(wtxn, 1)
	wtxn.Commit()
	rtxn := db.ReadTxn()
	_ = rtxn
}

func multipleWriteTxns(db *statedb.DB, foo, bar statedb.RWTable[int]) {
	wtxn1 := db.WriteTxn(foo)
	wtxn2 := db.WriteTxn(bar) // want `opening WriteTxn while transaction "wtxn1" is still live; use only one live transaction at a time`
	foo.Insert(wtxn1, 1)
	bar.Insert(wtxn2, 1)
	wtxn1.Commit()
	wtxn2.Commit()
}

func makeUnknownWriteTxn() statedb.WriteTxn {
	return nil
}

func okUnknownWriteTxn(foo statedb.RWTable[int]) {
	wtxn := makeUnknownWriteTxn()
	foo.Insert(wtxn, 1)
}

type txnHolder struct {
	db  *statedb.DB
	tbl statedb.RWTable[int]
	txn atomic.Pointer[statedb.WriteTxn]
}

func (h *txnHolder) okTxnPointerFallback() {
	txnPtr := h.txn.Load()
	if txnPtr == nil {
		fallbackTxn := h.db.WriteTxn(h.tbl)
		defer fallbackTxn.Commit()
		txnPtr = &fallbackTxn
	}
	h.tbl.Insert(*txnPtr, 1)
}
