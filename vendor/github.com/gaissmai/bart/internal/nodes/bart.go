// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"iter"

	"github.com/gaissmai/bart/internal/lpm"
	"github.com/gaissmai/bart/internal/sparse"
	"github.com/gaissmai/bart/internal/value"
)

// BartNode is a trie level node in the multibit routing table.
//
// Each BartNode contains two conceptually different arrays:
//   - Prefixes stores routing entries (prefix -> value),
//     laid out as a complete binary tree using the baseIndex()
//     function from the ART algorithm.
//   - Children: holding subtries or path-compressed leaves/fringes with
//     a branching factor of 256 (8 bits per stride).
//   - Children holds subnodes for the 256 possible next-hop paths
//     at this trie level (8-bit stride).
//
// Entries in Children may be:
//   - *BartNode[V]   -> internal child node for further traversal
//   - *LeafNode[V]   -> path-comp. node (depth < maxDepth - 1)
//   - *FringeNode[V] -> path-comp. node (depth == maxDepth - 1, stride-aligned: /8, /16, ... /128)
//
// Note: Both *LeafNode and *FringeNode entries are only created by path compression.
// Prefixes that match exactly at the maximum trie depth (depth == maxDepth) are
// never stored as Children, but always directly in the prefixes array at that level.
//
// Unlike the original ART, this implementation uses popcount-compressed sparse arrays
// instead of fixed-size arrays. Array slots are not pre-allocated; insertion
// and lookup rely on fast bitset operations and precomputed rank indexes.
type BartNode[V any] struct {
	Prefixes sparse.Array256[V]
	Children sparse.Array256[any]
}

// IsEmpty returns true if the node contains no routing entries (prefixes)
// and no child nodes. Empty nodes are candidates for compression or removal
// during trie optimization.
func (n *BartNode[V]) IsEmpty() bool {
	if n == nil {
		return true
	}
	return n.Prefixes.Len() == 0 && n.Children.Len() == 0
}

// PrefixCount returns the number of prefixes stored in this node.
func (n *BartNode[V]) PrefixCount() int {
	return n.Prefixes.Len()
}

// ChildCount returns the number of slots used in this node.
func (n *BartNode[V]) ChildCount() int {
	return n.Children.Len()
}

// InsertPrefix adds or updates a routing entry at the specified index with the given value.
// It returns true if a prefix already existed at that index (indicating an update),
// false if this is a new insertion.
func (n *BartNode[V]) InsertPrefix(idx uint8, val V) (exists bool) {
	return n.Prefixes.InsertAt(idx, val)
}

// GetPrefix retrieves the value associated with the prefix at the given index.
// Returns the value and true if found, or zero value and false if not present.
func (n *BartNode[V]) GetPrefix(idx uint8) (val V, exists bool) {
	return n.Prefixes.Get(idx)
}

// MustGetPrefix retrieves the value at the specified index, panicking if not found.
// This method should only be used when the caller is certain the index exists.
func (n *BartNode[V]) MustGetPrefix(idx uint8) (val V) {
	return n.Prefixes.MustGet(idx)
}

// AllIndices returns an iterator over all prefix entries.
// Each iteration yields the prefix index (uint8) and its associated value (V).
func (n *BartNode[V]) AllIndices() iter.Seq2[uint8, V] {
	return func(yield func(uint8, V) bool) {
		var buf [256]uint8
		for _, idx := range n.Prefixes.AsSlice(&buf) {
			val := n.MustGetPrefix(idx)
			if !yield(idx, val) {
				return
			}
		}
	}
}

// DeletePrefix removes the prefix at the specified index.
// Returns true if the prefix existed, otherwise false.
func (n *BartNode[V]) DeletePrefix(idx uint8) (exists bool) {
	_, exists = n.Prefixes.DeleteAt(idx)
	return exists
}

// InsertChild adds a child node at the specified address (0-255).
// The child can be a *BartNode[V], *LeafNode[V], or *FringeNode[V].
// Returns true if a child already existed at that address.
func (n *BartNode[V]) InsertChild(addr uint8, child any) (exists bool) {
	return n.Children.InsertAt(addr, child)
}

// GetChild retrieves the child node at the specified address.
// Returns the child and true if found, or nil and false if not present.
func (n *BartNode[V]) GetChild(addr uint8) (any, bool) {
	return n.Children.Get(addr)
}

// MustGetChild retrieves the child at the specified address, panicking if not found.
// This method should only be used when the caller is certain the child exists.
func (n *BartNode[V]) MustGetChild(addr uint8) any {
	return n.Children.MustGet(addr)
}

// AllChildren returns an iterator over all child nodes.
// Each iteration yields the child's address (uint8) and the child node (any).
func (n *BartNode[V]) AllChildren() iter.Seq2[uint8, any] {
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
func (n *BartNode[V]) DeleteChild(addr uint8) (exists bool) {
	_, exists = n.Children.DeleteAt(addr)
	return exists
}

// Contains returns true if an index (idx) has any matching longest-prefix
// in the current node’s prefix table.
//
// This function performs a presence check without retrieving the associated value.
// It is faster than a full lookup, as it only tests for intersection with the
// backtracking bitset for the given index.
//
// The prefix table is structured as a complete binary tree (CBT), and LPM testing
// is done via a bitset operation that maps the traversal path from the given index
// toward its possible ancestors.
func (n *BartNode[V]) Contains(idx uint8) bool {
	return n.Prefixes.Intersects(&lpm.LookupTbl[idx])
}

// LookupIdx performs a longest-prefix match (LPM) lookup for the given index (idx)
// within the 8-bit stride-based prefix table at this trie depth.
//
// The function returns the matched base index, associated value, and true if a
// matching prefix exists at this level; otherwise, ok is false.
//
// Internally, the prefix table is organized as a complete binary tree (CBT) indexed
// via the baseIndex function. Unlike the original ART algorithm, this implementation
// does not use an allotment-based approach. Instead, it performs CBT backtracking
// using a bitset-based operation with a precomputed backtracking pattern specific to idx.
func (n *BartNode[V]) LookupIdx(idx uint8) (top uint8, val V, ok bool) {
	// top is the idx of the longest-prefix-match
	if top, ok = n.Prefixes.IntersectionTop(&lpm.LookupTbl[idx]); ok {
		return top, n.MustGetPrefix(top), true
	}
	return top, val, ok
}

// Lookup is just a simple wrapper for lookupIdx.
func (n *BartNode[V]) Lookup(idx uint8) (val V, ok bool) {
	_, val, ok = n.LookupIdx(idx)
	return val, ok
}

// CloneFlat returns a shallow copy of the current node, optionally performing deep copies of values.
//
// If cloneFn is nil, the stored values in prefixes are copied directly without modification.
// Otherwise, cloneFn is applied to each stored value for deep cloning.
// Child nodes are cloned shallowly: LeafNode and FringeNode children are cloned via their clone methods,
// but child nodes of type *BartNode[V] (subnodes) are assigned as-is without recursive cloning.
// This method does not recursively clone descendants beyond the immediate children.
//
// Note: The returned node is a new instance with copied slices but only shallow copies of nested nodes,
// except for LeafNode and FringeNode children which are cloned according to cloneFn.
func (n *BartNode[V]) CloneFlat(cloneFn value.CloneFunc[V]) *BartNode[V] {
	if n == nil {
		return nil
	}

	c := new(BartNode[V])
	if n.IsEmpty() {
		return c
	}

	// copy ...
	c.Prefixes = *(n.Prefixes.Copy())

	// ... and clone the values
	if cloneFn != nil {
		for i, v := range c.Prefixes.Items {
			c.Prefixes.Items[i] = cloneFn(v)
		}
	}

	// copy ...
	c.Children = *(n.Children.Copy())

	// Iterate over children to flat clone leaf/fringe nodes;
	// for *BartNode[V] children, keep shallow references (no recursive clone)
	for i, anyKid := range c.Children.Items {
		switch kid := anyKid.(type) {
		case *BartNode[V]:
			// Shallow copy
		case *LeafNode[V]:
			// Clone leaf nodes, applying cloneFn as needed
			c.Children.Items[i] = kid.CloneLeaf(cloneFn)
		case *FringeNode[V]:
			// Clone fringe nodes, applying cloneFn as needed
			c.Children.Items[i] = kid.CloneFringe(cloneFn)
		default:
			panic("logic error, wrong node type")
		}
	}

	return c
}

// CloneRec performs a recursive deep copy of the node and all its descendants.
//
// If cloneFn is nil, the stored values are copied directly without modification.
// Otherwise cloneFn is applied to each stored value for deep cloning.
//
// This method first creates a shallow clone of the current node using CloneFlat,
// applying cloneFn to values as described there. Then it recursively clones all
// child nodes of type *BartNode[V], performing a full deep clone down the subtree.
//
// Child nodes of type *LeafNode[V] and *FringeNode[V] are already cloned
// by CloneFlat.
//
// Returns a new instance of BartNode[V] which is a complete deep clone of the
// receiver node with all descendants.
func (n *BartNode[V]) CloneRec(cloneFn value.CloneFunc[V]) *BartNode[V] {
	if n == nil {
		return nil
	}

	// Perform a flat clone of the current node.
	c := n.CloneFlat(cloneFn)

	// Recursively clone all child nodes of type *BartNode[V]
	for i, kidAny := range c.Children.Items {
		if kid, ok := kidAny.(*BartNode[V]); ok {
			c.Children.Items[i] = kid.CloneRec(cloneFn)
		}
	}

	return c
}
