// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"iter"
	"slices"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
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
		for x, _ := range seq {
			if !yield(x) {
				break
			}
		}
	}
}

// partSeq returns a sequence of objects from a part Iterator.
func partSeq[Obj any](iter *part.Iterator[object]) iter.Seq2[Obj, Revision] {
	return func(yield func(Obj, Revision) bool) {
		// Iterate over a clone of the original iterator to allow the sequence to be iterated
		// from scratch multiple times.
		it := iter.Clone()
		for {
			_, iobj, ok := it.Next()
			if !ok {
				break
			}
			if !yield(iobj.data.(Obj), iobj.revision) {
				break
			}
		}
	}
}

// nonUniqueSeq returns a sequence of objects for a non-unique index.
// Non-unique indexes work by concatenating the secondary key with the
// primary key and then prefix searching for the items:
//
//	<secondary><primary><secondary length>
//	^^^^^^^^^^^
//
// Since the primary key can be of any length and we're prefix searching,
// we need to iterate over all objects matching the prefix and only emitting
// those which have the correct secondary key length.
// For example if we search for the key "aaaa", then we might have the following
// matches (_ is just delimiting, not part of the key):
//
//	aaaa_bbb4
//	aaa_abab3
//	aaaa_ccc4
//
// We yield "aaaa_bbb4", skip "aaa_abab3" and yield "aaaa_ccc4".
func nonUniqueSeq[Obj any](iter *part.Iterator[object], searchKey []byte) iter.Seq2[Obj, Revision] {
	return func(yield func(Obj, Revision) bool) {
		// Clone the iterator to allow multiple iterations over the sequence.
		it := iter.Clone()
		for {
			key, iobj, ok := it.Next()
			if !ok {
				break
			}

			_, secondary := decodeNonUniqueKey(key)

			// The secondary key doesn't match the search key. Since the primary
			// key length can vary, we need to continue the prefix search.
			if len(secondary) != len(searchKey) {
				continue
			}

			if !yield(iobj.data.(Obj), iobj.revision) {
				break
			}
		}
	}
}

// iterator adapts the "any" object iterator to a typed object.
type iterator[Obj any] struct {
	iter interface{ Next() ([]byte, object, bool) }
}

func (it *iterator[Obj]) Next() (obj Obj, revision uint64, ok bool) {
	_, iobj, ok := it.iter.Next()
	if ok {
		obj = iobj.data.(Obj)
		revision = iobj.revision
	}
	return
}

func NewDualIterator[Obj any](left, right Iterator[Obj]) *DualIterator[Obj] {
	return &DualIterator[Obj]{
		left:  iterState[Obj]{iter: left},
		right: iterState[Obj]{iter: right},
	}
}

type iterState[Obj any] struct {
	iter Iterator[Obj]
	obj  Obj
	rev  Revision
	ok   bool
}

// DualIterator allows iterating over two iterators in revision order.
// Meant to be used for combined iteration of LowerBound(ByRevision)
// and Deleted().
type DualIterator[Obj any] struct {
	left  iterState[Obj]
	right iterState[Obj]
}

func (it *DualIterator[Obj]) Next() (obj Obj, revision uint64, fromLeft, ok bool) {
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
	iter           *DualIterator[Obj]
	watch          <-chan struct{}
}

func (it *changeIterator[Obj]) refresh(txn ReadTxn) {
	// Instead of indexReadTxn() we look up directly here so we don't
	// refresh from mutated indexes in case [txn] is a WriteTxn. This
	// is important as the WriteTxn may be aborted and thus revisions will
	// reset back and watermarks bumped from here would be invalid.
	itxn := txn.getTxn()
	indexEntry := itxn.root[it.table.tablePos()].indexes[RevisionIndexPos]
	indexTxn := indexReadTxn{indexEntry.tree, indexEntry.unique}
	updateIter := &iterator[Obj]{indexTxn.LowerBound(index.Uint64(it.revision + 1))}
	deleteIter := it.dt.deleted(itxn, it.deleteRevision+1)
	it.iter = NewDualIterator(deleteIter, updateIter)

	// It is enough to watch the revision index and not the graveyard since
	// any object that is inserted into the graveyard will be deleted from
	// the revision index.
	it.watch = indexTxn.RootWatch()
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
		for obj, rev, deleted, ok := it.iter.Next(); ok; obj, rev, deleted, ok = it.iter.Next() {
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

func (it *changeIterator[Obj]) close() {
	if it.dt != nil {
		it.dt.close()
	}
	it.dt = nil
}

type anyChangeIterator interface {
	nextAny(ReadTxn) (iter.Seq2[Change[any], Revision], <-chan struct{})
}
