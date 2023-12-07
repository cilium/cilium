// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

// Config defines the command-line configuration for the memos
// example application.
type Config struct {
	Directory string // the directory in which memos are stored.
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("directory", "memos", "Memo directory")
}

// Memo is a brief note stored in the memos directory. A memo
// can be created with the /memos API.
type Memo struct {
	Name    string            // filename of the memo. Stored in <directory>/<name>.
	Content string            // contents of the memo.
	Status  reconciler.Status // reconciliation status
}

// GetStatus returns the reconciliation status. Used to provide the
// reconciler access to it.
func (memo *Memo) GetStatus() reconciler.Status {
	return memo.Status
}

// WithStatus returns a copy of the memo with a new reconciliation status.
// Used by the reconciler to update the reconciliation status of the memo.
func (memo *Memo) WithStatus(newStatus reconciler.Status) *Memo {
	return &Memo{
		Name:    memo.Name,
		Content: memo.Content,
		Status:  newStatus,
	}
}

// MemoNameIndex allows looking up the memo by its name, e.g.
// memos.First(txn, MemoNameIndex.Query("my-memo"))
var MemoNameIndex = statedb.Index[*Memo, string]{
	Name: "name",
	FromObject: func(memo *Memo) index.KeySet {
		return index.NewKeySet(index.String(memo.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

// MemoStatusIndex indexes memos by their reconciliation status.
// This is mainly used by the reconciler to implement WaitForReconciliation.
var MemoStatusIndex = reconciler.NewStatusIndex[*Memo]((*Memo).GetStatus)

// NewMemoTable creates and registers the memos table.
func NewMemoTable(db *statedb.DB) (statedb.RWTable[*Memo], statedb.Index[*Memo, reconciler.StatusKind], error) {
	tbl, err := statedb.NewTable[*Memo](
		"memos",
		MemoNameIndex,
		MemoStatusIndex,
	)
	if err == nil {
		err = db.RegisterTable(tbl)
	}
	return tbl, MemoStatusIndex, err
}
