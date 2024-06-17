// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

type DeriveResult int

const (
	DeriveInsert DeriveResult = 0 // Insert the object
	DeriveUpdate DeriveResult = 1 // Update the object (if it exists)
	DeriveDelete DeriveResult = 2 // Delete the object
	DeriveSkip   DeriveResult = 3 // Skip
)

type DeriveParams[In, Out any] struct {
	cell.In

	Lifecycle cell.Lifecycle
	Jobs      job.Registry
	Health    cell.Health
	DB        *DB
	InTable   Table[In]
	OutTable  RWTable[Out]
}

// Derive constructs and registers a job to transform objects from the input table to the
// output table, e.g. derive the output table from the input table. Useful when constructing
// a reconciler that has its desired state solely derived from a single table. For example
// the bandwidth manager's desired state is directly derived from the devices table.
//
// Derive is parametrized with the transform function that transforms the input object
// into the output object. If the transform function returns false, then the object
// is skipped.
//
// Example use:
//
//	cell.Invoke(
//	  statedb.Derive[*tables.Device, *Foo](
//	    func(d *Device, deleted bool) (*Foo, DeriveResult) {
//	      if deleted {
//	        return &Foo{Index: d.Index}, DeriveDelete
//	      }
//	      return &Foo{Index: d.Index}, DeriveInsert
//	    }),
//	)
func Derive[In, Out any](jobName string, transform func(obj In, deleted bool) (Out, DeriveResult)) func(DeriveParams[In, Out]) {
	return func(p DeriveParams[In, Out]) {
		g := p.Jobs.NewGroup(p.Health)
		g.Add(job.OneShot(
			jobName,
			derive[In, Out]{p, jobName, transform}.loop),
		)
		p.Lifecycle.Append(g)
	}

}

type derive[In, Out any] struct {
	DeriveParams[In, Out]
	jobName   string
	transform func(obj In, deleted bool) (Out, DeriveResult)
}

func (d derive[In, Out]) loop(ctx context.Context, _ cell.Health) error {
	out := d.OutTable
	txn := d.DB.WriteTxn(d.InTable)
	iter, err := d.InTable.Changes(txn)
	txn.Commit()
	if err != nil {
		return err
	}
	defer iter.Close()
	for {
		wtxn := d.DB.WriteTxn(out)
		for ev, _, ok := iter.Next(); ok; ev, _, ok = iter.Next() {
			outObj, result := d.transform(ev.Object, ev.Deleted)
			switch result {
			case DeriveInsert:
				_, _, err = out.Insert(wtxn, outObj)
			case DeriveUpdate:
				_, _, found := out.Get(wtxn, out.PrimaryIndexer().QueryFromObject(outObj))
				if found {
					_, _, err = out.Insert(wtxn, outObj)
				}
			case DeriveDelete:
				_, _, err = out.Delete(wtxn, outObj)
			case DeriveSkip:
			}
			if err != nil {
				wtxn.Abort()
				return err
			}
		}
		wtxn.Commit()

		select {
		case <-iter.Watch(d.DB.ReadTxn()):
		case <-ctx.Done():
			return nil
		}
	}
}
