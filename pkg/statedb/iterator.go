// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import memdb "github.com/hashicorp/go-memdb"

type filterIterator[Obj any] struct {
	Iterator[Obj]
	keep func(obj Obj) bool
}

func (it filterIterator[Obj]) Next() (obj Obj, ok bool) {
	for {
		obj, ok = it.Iterator.Next()
		if !ok {
			return
		}
		if it.keep(obj) {
			return
		}
	}
}

// Filter wraps an iterator that only returns the objects for which 'keep' returns
// true.
func Filter[Obj any](it Iterator[Obj], keep func(obj Obj) bool) Iterator[Obj] {
	return filterIterator[Obj]{Iterator: it, keep: keep}
}

// Collect collects the object returned by the iterator into a slice.
func Collect[Obj any](iter Iterator[Obj]) []Obj {
	out := make([]Obj, 0, 64)
	for obj, ok := iter.Next(); ok; obj, ok = iter.Next() {
		out = append(out, obj)
	}
	return out
}

// ProcessEach invokes the given function for each object provided by the iterator.
func ProcessEach[Obj any, It Iterator[Obj]](iter It, fn func(Obj) error) (err error) {
	for obj, ok := iter.Next(); ok; obj, ok = iter.Next() {
		err = fn(obj)
		if err != nil {
			return
		}
	}
	return
}

// Length consumes the iterator and returns the number of items consumed.
func Length[Obj any, It Iterator[Obj]](iter It) (n int) {
	for _, ok := iter.Next(); ok; _, ok = iter.Next() {
		n++
	}
	return
}

// iterator implements type-safe iteration around the go-memdb's ResultIterator.
// This implements both the Iterator and the WatchableIterator. The query method
// should take care to not return the iterator as WatchableIterator if WatchCh()
// is not supported (e.g. if it's LowerBound).
type iterator[Obj any] struct {
	it memdb.ResultIterator
}

func (s iterator[Obj]) Next() (obj Obj, ok bool) {
	if v := s.it.Next(); v != nil {
		obj = v.(Obj)
		ok = true
	}
	return
}

func (s iterator[Obj]) Invalidated() <-chan struct{} {
	ch := s.it.WatchCh()
	if ch == nil {
		// Some iterators don't support watching. The normal Iterator[] type
		// should be used and not the WatchableIterator[].
		panic("Internal error: WatchCH() returned nil. This query should return plain Iterator[] instead?")
	}
	return ch
}
