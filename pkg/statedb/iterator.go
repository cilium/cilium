// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
)

// Collect creates a slice of objects out of the iterator.
// The iterator is consumed in the process.
func Collect[Obj any](iter Iterator[Obj]) []Obj {
	objs := []Obj{}
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		objs = append(objs, obj)
	}
	return objs
}

// CollectSet creates a set of objects out of the iterator.
// The iterator is consumed in the process.
func CollectSet[Obj comparable](iter Iterator[Obj]) sets.Set[Obj] {
	objs := sets.New[Obj]()
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		objs.Insert(obj)
	}
	return objs
}

// ProcessEach invokes the given function for each object provided by the iterator.
func ProcessEach[Obj any, It Iterator[Obj]](iter It, fn func(Obj, Revision) error) (err error) {
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		err = fn(obj, rev)
		if err != nil {
			return
		}
	}
	return
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
