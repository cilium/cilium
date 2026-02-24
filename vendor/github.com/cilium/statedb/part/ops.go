// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

// Ops is the common operations that can be performed with a Tree
// or Txn.
type Ops[T any] interface {
	// Len returns the number of objects in the tree.
	Len() int

	// Get fetches the value associated with the given key.
	// Returns the value, a watch channel (which is closed on
	// modification to the key) and boolean which is true if
	// value was found.
	Get(key []byte) (T, <-chan struct{}, bool)

	// Prefix returns an iterator for all objects that starts with the
	// given prefix, and a channel that closes when any objects matching
	// the given prefix are upserted or deleted.
	Prefix(key []byte) (*Iterator[T], <-chan struct{})

	// LowerBound returns an iterator for all objects that have a
	// key equal or higher than the given 'key'.
	LowerBound(key []byte) *Iterator[T]

	// RootWatch returns a watch channel for the root of the tree.
	// Since this is the channel associated with the root, this closes
	// when there are any changes to the tree.
	RootWatch() <-chan struct{}

	// Iterator returns an iterator for all objects.
	Iterator() *Iterator[T]

	// PrintTree to the standard output. For debugging.
	PrintTree()
}

var (
	_ Ops[int] = &Tree[int]{}
	_ Ops[int] = &Txn[int]{}
)
