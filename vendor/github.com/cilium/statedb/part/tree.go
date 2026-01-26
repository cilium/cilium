// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"fmt"
	"sync/atomic"
)

// Tree is a persistent (immutable) adaptive radix tree. It supports
// map-like operations on values keyed by []byte and additionally
// prefix searching and lower bound searching. Each node in the tree
// has an associated channel that is closed when that node is mutated.
// This allows watching any part of the tree (any prefix) for changes.
type Tree[T any] struct {
	root      *header[T]
	rootWatch chan struct{}
	size      int // the number of objects in the tree
	opts      options
	prevTxn   *atomic.Pointer[Txn[T]] // the previous txn for reusing the allocation
	nextTxnID uint64                  // the next transaction ID to use
}

// New constructs a new tree.
func New[T any](opts ...Option) Tree[T] {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	t := Tree[T]{
		root:      nil,
		rootWatch: make(chan struct{}),
		size:      0,
		opts:      o,
		prevTxn:   &atomic.Pointer[Txn[T]]{},
	}
	return t
}

type Option func(*options)

// RootOnlyWatch sets the tree to only have a watch channel on the root
// node. This improves the speed at the cost of having a much more coarse
// grained notifications.
var RootOnlyWatch = (*options).setRootOnlyWatch

func newTxn[T any](o options) *Txn[T] {
	txn := &Txn[T]{
		watches: make(map[chan struct{}]struct{}),
	}
	txn.deleteParentsCache = make([]deleteParent[T], 0, 32)
	txn.opts = o
	return txn
}

// Txn constructs a new transaction against the tree. Transactions
// enable efficient large mutations of the tree by caching cloned
// nodes. Only a single transaction can be in flight at a time.
func (t *Tree[T]) Txn() *Txn[T] {
	var txn *Txn[T]

	// Reuse the previous txn allocation if possible
	if prevTxn := t.prevTxn.Swap(nil); prevTxn != nil {
		txn = prevTxn
		clear(txn.watches)
		txn.dirty = false
	} else {
		txn = newTxn[T](t.opts)
	}
	txn.opts = t.opts
	txn.root = t.root
	txn.oldRoot = t.root
	txn.rootWatch = t.rootWatch
	txn.size = t.size
	txn.prevTxn = t.prevTxn
	txn.txnID = t.nextTxnID
	return txn
}

// Len returns the number of objects in the tree.
func (t *Tree[T]) Len() int {
	return t.size
}

// Get fetches the value associated with the given key.
// Returns the value, a watch channel (which is closed on
// modification to the key) and boolean which is true if
// value was found.
func (t *Tree[T]) Get(key []byte) (T, <-chan struct{}, bool) {
	value, watch, ok := search(t.root, t.rootWatch, key)
	return value, watch, ok
}

// Prefix returns an iterator for all objects that starts with the
// given prefix, and a channel that closes when any objects matching
// the given prefix are upserted or deleted.
func (t *Tree[T]) Prefix(prefix []byte) (Iterator[T], <-chan struct{}) {
	return prefixSearch(t.root, t.rootWatch, prefix)
}

// RootWatch returns a watch channel for the root of the tree.
// Since this is the channel associated with the root, this closes
// when there are any changes to the tree.
func (t *Tree[T]) RootWatch() <-chan struct{} {
	return t.rootWatch
}

// LowerBound returns an iterator for all keys that have a value
// equal to or higher than 'key'.
func (t *Tree[T]) LowerBound(key []byte) Iterator[T] {
	return lowerbound(t.root, key)
}

// Insert inserts the key into the tree with the given value.
// Returns the old value if it exists and a new tree.
func (t *Tree[T]) Insert(key []byte, value T) (old T, hadOld bool, tree Tree[T]) {
	txn := t.Txn()
	old, hadOld = txn.Insert(key, value)
	tree = txn.CommitAndNotify()
	return
}

// Modify a value in the tree. If the key does not exist the modify
// function is called with the zero value for T. It is up to the
// caller to not mutate the value in-place and to return a clone.
// Returns the old value if it exists.
func (t *Tree[T]) Modify(key []byte, value T, mod func(T, T) T) (old T, hadOld bool, tree Tree[T]) {
	txn := t.Txn()
	old, hadOld = txn.Modify(key, value, mod)
	tree = txn.CommitAndNotify()
	return
}

// Delete the given key from the tree.
// Returns the old value if it exists and the new tree.
func (t *Tree[T]) Delete(key []byte) (old T, hadOld bool, tree Tree[T]) {
	txn := t.Txn()
	old, hadOld = txn.Delete(key)
	tree = txn.CommitAndNotify()
	return
}

// Iterator returns an iterator for all objects.
func (t *Tree[T]) Iterator() Iterator[T] {
	return newIterator(t.root)
}

// All iterates over all objects
func (t *Tree[T]) All(yield func([]byte, T) bool) {
	Iterator[T]{start: t.root}.All(yield)
}

// PrintTree to the standard output. For debugging.
func (t *Tree[T]) PrintTree() {
	fmt.Printf("rootWatch: %p %v\n", t.rootWatch, isClosedChan(t.rootWatch))
	t.root.printTree(0)
}
