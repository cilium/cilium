// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

// MemoOps writes [Memo]s to disk.
// Implements the Reconciler.Operations[*Memo] API.
type MemoOps struct {
	log       logrus.FieldLogger
	directory string
}

// NewMemoOps creates the memo operations.
func NewMemoOps(lc cell.Lifecycle, log logrus.FieldLogger, cfg Config) reconciler.Operations[*Memo] {
	ops := &MemoOps{directory: cfg.Directory, log: log}

	// Register the Start and Stop methods to be called when the application
	// starts and stops respectively. The start hook will create the
	// memo directory.
	lc.Append(ops)
	return ops
}

// Delete a memo.
func (ops *MemoOps) Delete(ctx context.Context, txn statedb.ReadTxn, memo *Memo) error {
	filename := path.Join(ops.directory, memo.Name)
	err := os.Remove(filename)
	ops.log.Infof("Delete(%s): %s", filename, err)
	return err
}

// Prune unexpected memos.
func (ops *MemoOps) Prune(ctx context.Context, txn statedb.ReadTxn, iter statedb.Iterator[*Memo]) error {
	expected := sets.New[string]()
	for memo, _, ok := iter.Next(); ok; memo, _, ok = iter.Next() {
		expected.Insert(memo.Name)
	}

	// Find unexpected files
	unexpected := sets.New[string]()
	if entries, err := os.ReadDir(ops.directory); err != nil {
		return err
	} else {
		for _, entry := range entries {
			if !expected.Has(entry.Name()) {
				unexpected.Insert(entry.Name())
			}
		}
	}

	// ... and remove them.
	var errs []error
	for name := range unexpected {
		filename := path.Join(ops.directory, name)
		err := os.Remove(filename)
		ops.log.Infof("Prune(%s): %v", filename, err)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Update a memo.
func (ops *MemoOps) Update(ctx context.Context, txn statedb.ReadTxn, memo *Memo, changed *bool) error {
	filename := path.Join(ops.directory, memo.Name)

	// Read the old file to figure out if it had changed.
	// The 'changed' boolean is used by full reconciliation to keep track of when the target
	// has gone out-of-sync (e.g. there has been some outside influence to it).
	old, err := os.ReadFile(filename)
	if err == nil && bytes.Equal(old, []byte(memo.Content)) {

		// Nothing to do.
		return nil
	}
	if changed != nil {
		*changed = true
	}
	err = os.WriteFile(filename, []byte(memo.Content), 0644)
	ops.log.Infof("Update(%s): %v", filename, err)
	return err
}

var _ reconciler.Operations[*Memo] = &MemoOps{}

func (ops *MemoOps) Start(cell.HookContext) error {
	return os.MkdirAll(ops.directory, 0755)
}

func (*MemoOps) Stop(cell.HookContext) error {
	return nil
}

var _ cell.HookInterface = &MemoOps{}
