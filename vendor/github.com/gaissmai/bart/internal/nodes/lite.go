// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"iter"

	"github.com/gaissmai/bart/internal/bitset"
	"github.com/gaissmai/bart/internal/lpm"
	"github.com/gaissmai/bart/internal/sparse"
	"github.com/gaissmai/bart/internal/value"
)

// LiteNode is a trie level node in the multibit routing table.
//
// Each LiteNode contains two conceptually different bitset-based arrays:
//   - Prefixes: a BitSet256 tracking which prefix indices are occupied,
//     with Count tracking the number of active entries.
//   - Children: holding subtries or path-compressed leaves/fringes with
//     a branching factor of 256 (8 bits per stride).
//
// Entries in Children may be:
//   - *LiteNode[V]   -> internal child node for further traversal
//   - *LeafNode[V]   -> path-comp. node (depth < maxDepth - 1)
//   - *FringeNode[V] -> path-comp. node (depth == maxDepth - 1, stride-aligned)
//
// Note: The type parameter V is a phantom type used solely for common
// method generation; LiteNode stores no values.
type LiteNode[V any] struct {
	Children sparse.Array256[any]
	Prefixes struct {
		// no values
		bitset.BitSet256
		Count uint16
	}
}

// IsEmpty returns true if the node contains no routing entries (prefixes)
// and no child nodes. Empty nodes are candidates for compression or removal
// during trie optimization.
func (n *LiteNode[V]) IsEmpty() bool {
	if n == nil {
		return true
	}
	return n.Prefixes.Count == 0 && n.Children.Len() == 0
}

// PrefixCount returns the number of prefixes stored in this node.
func (n *LiteNode[V]) PrefixCount() int {
	return int(n.Prefixes.Count)
}

// ChildCount returns the number of slots used in this node.
func (n *LiteNode[V]) ChildCount() int {
	return n.Children.Len()
}

// InsertPrefix adds a routing entry at the specified index.
// It returns true if a prefix already existed at that index
// false if this is a new insertion.
func (n *LiteNode[V]) InsertPrefix(idx uint8, _ V) (exists bool) {
	if exists = n.Prefixes.Test(idx); exists {
		return exists
	}
	n.Prefixes.Set(idx)
	n.Prefixes.Count++
	return exists
}

// prefix is set at the given index.
func (n *LiteNode[V]) GetPrefix(idx uint8) (_ V, exists bool) {
	exists = n.Prefixes.Test(idx)
	return
}

func (n *LiteNode[V]) MustGetPrefix(idx uint8) (_ V) {
	return
}

// AllIndices returns an iterator over all prefix entries.
// Each iteration yields the prefix index (uint8) and its associated value (V).
func (n *LiteNode[V]) AllIndices() iter.Seq2[uint8, V] {
	var zero V
	return func(yield func(uint8, V) bool) {
		var buf [256]uint8
		for _, idx := range n.Prefixes.AsSlice(&buf) {
			if !yield(idx, zero) {
				return
			}
		}
	}
}

// DeletePrefix removes the prefix at the specified index.
// Returns true if the prefix existed, and false otherwise.
func (n *LiteNode[V]) DeletePrefix(idx uint8) (exists bool) {
	if exists = n.Prefixes.Test(idx); !exists {
		return false
	}
	n.Prefixes.Clear(idx)
	n.Prefixes.Count--
	return true
}

// InsertChild adds a child node at the specified address (0-255).
// The child can be a *LiteNode[V], *LeafNode, or *FringeNode.
// Returns true if a child already existed at that address.
func (n *LiteNode[V]) InsertChild(addr uint8, child any) (exists bool) {
	return n.Children.InsertAt(addr, child)
}

// GetChild retrieves the child node at the specified address.
// Returns the child and true if found, or nil and false if not present.
func (n *LiteNode[V]) GetChild(addr uint8) (any, bool) {
	return n.Children.Get(addr)
}

// MustGetChild retrieves the child at the specified address, panicking if not found.
// This method should only be used when the caller is certain the child exists.
func (n *LiteNode[V]) MustGetChild(addr uint8) any {
	return n.Children.MustGet(addr)
}

// AllChildren returns an iterator over all child nodes.
// Each iteration yields the child's address (uint8) and the child node (any).
func (n *LiteNode[V]) AllChildren() iter.Seq2[uint8, any] {
	return func(yield func(addr uint8, child any) bool) {
		var buf [256]uint8
		addrs := n.Children.AsSlice(&buf)
		for i, addr := range addrs {
			child := n.Children.Items[i]
			if !yield(addr, child) {
				return
			}
		}
	}
}

// DeleteChild removes the child node at the specified address.
// This operation is idempotent - removing a non-existent child is safe.
func (n *LiteNode[V]) DeleteChild(addr uint8) (exists bool) {
	_, exists = n.Children.DeleteAt(addr)
	return exists
}

// Contains returns true if an index (idx) has any matching longest-prefix
// in the current node’s prefix table.
//
// This function performs a presence check.
//
// The prefix table is structured as a complete binary tree (CBT), and LPM testing
// is done via a bitset operation that maps the traversal path from the given index
// toward its possible ancestors.
func (n *LiteNode[V]) Contains(idx uint8) bool {
	return n.Prefixes.Intersects(&lpm.LookupTbl[idx])
}

// LookupIdx performs a longest-prefix match (LPM) lookup for the given index (idx)
// within the 8-bit stride-based prefix table at this trie depth.
//
// The function returns the matched index and whether a matching prefix
// exists at this level. The value type parameter exists only to satisfy interfaces.
//
// Internally, the prefix table is organized as a complete binary tree (CBT) indexed
// via the baseIndex function. Unlike the original ART algorithm, this implementation
// does not use an allotment-based approach. Instead, it performs CBT backtracking
// using a bitset-based operation with a precomputed backtracking pattern specific to idx.
func (n *LiteNode[V]) LookupIdx(idx uint8) (top uint8, _ V, ok bool) {
	top, ok = n.Prefixes.IntersectionTop(&lpm.LookupTbl[idx])
	return
}

// Lookup is just a simple wrapper for lookupIdx.
func (n *LiteNode[V]) Lookup(idx uint8) (_ V, ok bool) {
	_, _, ok = n.LookupIdx(idx)
	return
}

// CloneFlat returns a shallow copy of the current node.
//
// CloneFn is only used for interface satisfaction.
func (n *LiteNode[V]) CloneFlat(_ value.CloneFunc[V]) *LiteNode[V] {
	if n == nil {
		return nil
	}

	c := new(LiteNode[V])
	if n.IsEmpty() {
		return c
	}

	// copy simple values
	c.Prefixes = n.Prefixes

	// sparse array
	c.Children = *(n.Children.Copy())

	// no values to copy
	return c
}

// CloneRec performs a recursive deep copy of the node and all its descendants.
//
// cloneFn is only used for interface satisfaction.
//
// It first creates a shallow clone of the current node using CloneFlat.
// Then it recursively clones all child nodes of type *LiteNode[V],
// performing a full deep clone down the subtree.
//
// Child nodes of type *LeafNode and *FringeNode are already copied
// by CloneFlat.
//
// Returns a new instance of LiteNode[V] which is a complete deep clone of the
// receiver node with all descendants.
func (n *LiteNode[V]) CloneRec(_ value.CloneFunc[V]) *LiteNode[V] {
	if n == nil {
		return nil
	}

	// Perform a flat clone of the current node.
	c := n.CloneFlat(nil)

	// Recursively clone all child nodes of type *LiteNode[V]
	for i, kidAny := range c.Children.Items {
		if kid, ok := kidAny.(*LiteNode[V]); ok {
			c.Children.Items[i] = kid.CloneRec(nil)
		}
	}

	return c
}
