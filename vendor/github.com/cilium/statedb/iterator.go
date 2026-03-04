// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"iter"
	"slices"

	"github.com/cilium/statedb/index"
)

// Collect creates a slice of objects out of the iterator.
// The iterator is consumed in the process.
func Collect[Obj any](seq iter.Seq2[Obj, Revision]) []Obj {
	return slices.Collect(ToSeq(seq))
}

// Map a function over a sequence of objects returned by
// a query.
func Map[In, Out any](seq iter.Seq2[In, Revision], fn func(In) Out) iter.Seq2[Out, Revision] {
	return func(yield func(Out, Revision) bool) {
		for obj, rev := range seq {
			if !yield(fn(obj), rev) {
				break
			}
		}
	}
}

func Filter[Obj any](seq iter.Seq2[Obj, Revision], keep func(Obj) bool) iter.Seq2[Obj, Revision] {
	return func(yield func(Obj, Revision) bool) {
		for obj, rev := range seq {
			if keep(obj) {
				if !yield(obj, rev) {
					break
				}
			}
		}
	}
}

// ToSeq takes a Seq2 and produces a Seq with the first element of the pair.
func ToSeq[A, B any](seq iter.Seq2[A, B]) iter.Seq[A] {
	return func(yield func(A) bool) {
		for x := range seq {
			if !yield(x) {
				break
			}
		}
	}
}

// Values takes a Seq2 and produces a Seq with the second element of the pair.
func Values[A, B any](seq iter.Seq2[A, B]) iter.Seq[B] {
	return func(yield func(B) bool) {
		for _, x := range seq {
			if !yield(x) {
				break
			}
		}
	}
}

func Just[A any](x A) iter.Seq[A] {
	return func(yield func(A) bool) {
		yield(x)
	}
}

func Just2[A, B any](a A, b B) iter.Seq2[A, B] {
	return func(yield func(A, B) bool) {
		yield(a, b)
	}
}

func objSeq[Obj any](iter tableIndexIterator) iter.Seq2[Obj, Revision] {
	return func(yield func(Obj, Revision) bool) {
		iter.All(func(_ []byte, iobj object) bool {
			return yield(iobj.data.(Obj), iobj.revision)
		})
	}
}

// iterator adapts the "any" object iterator to a typed object.
type iterator[Obj any] struct {
	next func() ([]byte, object, bool)
}

func (it iterator[Obj]) Next() (obj Obj, revision uint64, ok bool) {
	_, iobj, ok := it.next()
	if ok {
		obj = iobj.data.(Obj)
		revision = iobj.revision
	}
	return
}

func newDualIterator[Obj any](left, right *iterator[Obj]) *dualIterator[Obj] {
	return &dualIterator[Obj]{
		left:  iterState[Obj]{iter: left},
		right: iterState[Obj]{iter: right},
	}
}

type iterState[Obj any] struct {
	iter *iterator[Obj]
	obj  Obj
	rev  Revision
	ok   bool
}

// dualIterator allows iterating over two iterators in revision order.
// Meant to be used for combined iteration of LowerBound(ByRevision)
// and Deleted().
type dualIterator[Obj any] struct {
	left  iterState[Obj]
	right iterState[Obj]
}

func (it *dualIterator[Obj]) next() (obj Obj, revision uint64, fromLeft, ok bool) {
	// Advance the iterators
	if !it.left.ok && it.left.iter != nil {
		it.left.obj, it.left.rev, it.left.ok = it.left.iter.Next()
		if !it.left.ok {
			it.left.iter = nil
		}
	}
	if !it.right.ok && it.right.iter != nil {
		it.right.obj, it.right.rev, it.right.ok = it.right.iter.Next()
		if !it.right.ok {
			it.right.iter = nil
		}
	}

	// Find the lowest revision object
	switch {
	case !it.left.ok && !it.right.ok:
		ok = false
		return
	case it.left.ok && !it.right.ok:
		it.left.ok = false
		return it.left.obj, it.left.rev, true, true
	case it.right.ok && !it.left.ok:
		it.right.ok = false
		return it.right.obj, it.right.rev, false, true
	case it.left.rev <= it.right.rev:
		it.left.ok = false
		return it.left.obj, it.left.rev, true, true
	case it.right.rev <= it.left.rev:
		it.right.ok = false
		return it.right.obj, it.right.rev, false, true
	default:
		panic(fmt.Sprintf("BUG: Unhandled case: %+v", it))
	}
}

type changeIterator[Obj any] struct {
	table          Table[Obj]
	revision       Revision
	deleteRevision Revision
	dt             *deleteTracker[Obj]
	iter           *dualIterator[Obj]
	watch          <-chan struct{}
}

func (it *changeIterator[Obj]) refresh(txn ReadTxn) {
	tableEntry := txn.root()[it.table.tablePos()]
	if it.iter != nil && tableEntry.locked {
		var obj Obj
		panic(fmt.Sprintf("Table[%T].Changes().Next() called with the target table locked. This is not supported.", obj))
	}
	indexEntry := tableEntry.indexes[RevisionIndexPos]
	updated, _ := indexEntry.lowerBoundNext(index.Uint64(it.revision + 1))
	updateIter := &iterator[Obj]{updated}
	deleteIter := it.dt.deleted(txn, it.deleteRevision+1)
	it.iter = newDualIterator(deleteIter, updateIter)

	// It is enough to watch the revision index and not the graveyard since
	// any object that is inserted into the graveyard will be deleted from
	// the revision index.
	it.watch = indexEntry.rootWatch()
}

func (it *changeIterator[Obj]) Next(txn ReadTxn) (seq iter.Seq2[Change[Obj], Revision], watch <-chan struct{}) {
	if it.iter == nil {
		// Iterator has been exhausted, check if we need to requery
		// or whether we need to wait for changes first.
		select {
		case <-it.watch:
			// Watch channel closed, so new changes await
		default:
			// Watch channel for the query not closed yet, so return it to allow
			// caller to wait for the new changes.
			watch = it.watch
			seq = func(yield func(Change[Obj], Revision) bool) {}
			return
		}
	}

	// Refresh the iterator regardless if it was fully consumed or not to
	// pull in new changes. We keep returning a closed channel until the
	// iterator has been fully consumed. This does mean there's an extra
	// Next() call to get a proper watch channel, but it does make this
	// API much safer to use even when only partially consuming the
	// sequence.
	it.refresh(txn)
	watch = closedWatchChannel
	seq = func(yield func(Change[Obj], Revision) bool) {
		if it.iter == nil {
			return
		}
		for obj, rev, deleted, ok := it.iter.next(); ok; obj, rev, deleted, ok = it.iter.next() {
			if deleted {
				it.deleteRevision = rev
				it.dt.mark(rev)
			} else {
				it.revision = rev
			}
			change := Change[Obj]{
				Object:   obj,
				Revision: rev,
				Deleted:  deleted,
			}
			if !yield(change, rev) {
				return
			}
		}
		it.iter = nil
	}
	return
}

// changesAny is for implementing the /changes HTTP API where the concrete object
// type is not known.
func (it *changeIterator[Obj]) nextAny(txn ReadTxn) (iter.Seq2[Change[any], Revision], <-chan struct{}) {
	seq, watch := it.Next(txn)

	return func(yield func(Change[any], Revision) bool) {
		for change, rev := range seq {
			ok := yield(Change[any]{
				Object:   change.Object,
				Revision: change.Revision,
				Deleted:  change.Deleted,
			}, rev)
			if !ok {
				break
			}
		}
	}, watch
}

func (it *changeIterator[Obj]) Close() {
	it.iter = nil
	if it.dt != nil {
		it.dt.close()
	}
	it.dt = nil
}

type anyChangeIterator interface {
	nextAny(ReadTxn) (iter.Seq2[Change[any], Revision], <-chan struct{})
}
