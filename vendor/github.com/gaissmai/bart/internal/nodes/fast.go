// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"iter"

	"github.com/gaissmai/bart/internal/bitset"
	"github.com/gaissmai/bart/internal/lpm"
	"github.com/gaissmai/bart/internal/value"
)

// FastNode is a trie level node in the multibit routing table.
//
// Each FastNode contains two sections (Prefixes and Children), each with
// a BitSet256 tracking occupied indices and a fixed-size Items array:
//   - Prefixes.BitSet256: tracks which prefix indices are occupied.
//   - Prefixes.Items: [256]*V storing routing entry values.
//   - Children.BitSet256: tracks which child indices are occupied.
//   - Children.Items: [256]*any holding subtries or path-compressed leaves/fringes
//     (branching factor 256, 8 bits per stride).
//   - PfxCount: cached count of active prefixes (avoids BitSet.Size() calls).
//   - CldCount: cached count of child nodes (avoids BitSet.Size() calls).
//
// Prefixes use a complete binary tree layout driven by the baseIndex() function
// from the ART algorithm for fast LPM lookup.
//
// Entries in Children.Items (each *any containing a pointer) may be:
//   - **FastNode[V]   -> internal child node for further traversal
//   - **LeafNode[V]   -> path-comp. node (depth < maxDepth - 1)
//   - **FringeNode[V] -> path-comp. node (depth == maxDepth - 1, stride-aligned)
//
// Note: Children.Items uses *any (pointer to any) instead of any to reduce memory by
// ~30%, since many slots are nil and *any takes 1 word vs 2 words for nil any.
type FastNode[V any] struct {
	// Prefixes holding prefix -> value pointers, organized as a CBT
	// for fast LPM lookup within the node.
	Prefixes struct {
		bitset.BitSet256
		Items [256]*V
	}

	// Children holding subtries or path-compressed leaves or fringes.
	Children struct {
		bitset.BitSet256
		Items [256]*any // pointer to any, see explanation above
	}

	// PfxCount replaces expensive BitSet256.Size() calls. Automatically
	// maintained during InsertPrefix() and DeletePrefix() operations.
	PfxCount uint16

	// CldCount replaces expensive BitSet.Size() calls. Automatically
	// maintained during InsertChild() and DeleteChild() operations.
	CldCount uint16
}

// PrefixCount returns the number of prefixes stored in this node.
func (n *FastNode[V]) PrefixCount() int {
	return int(n.PfxCount)
}

// ChildCount returns the number of slots used in this node.
func (n *FastNode[V]) ChildCount() int {
	return int(n.CldCount)
}

// IsEmpty returns true if node has neither prefixes nor children
func (n *FastNode[V]) IsEmpty() bool {
	if n == nil {
		return true
	}
	return n.PfxCount == 0 && n.CldCount == 0
}

// GetChild returns the child node at the specified address and true if it exists.
// If no child exists at addr, returns nil and false.
func (n *FastNode[V]) GetChild(addr uint8) (any, bool) {
	if anyPtr := n.Children.Items[addr]; anyPtr != nil {
		return *anyPtr, true
	}
	return nil, false
}

// MustGetChild returns the child node at the specified address.
// Panics if no child exists at addr. This method should only be called
// when the caller has verified the child exists.
func (n *FastNode[V]) MustGetChild(addr uint8) any {
	// panics if n.children[addr] is nil
	return *n.Children.Items[addr]
}

// AllChildren returns an iterator over all child nodes.
// Each iteration yields the child's address (uint8) and the child node (any).
func (n *FastNode[V]) AllChildren() iter.Seq2[uint8, any] {
	return func(yield func(addr uint8, child any) bool) {
		var buf [256]uint8
		for _, addr := range n.Children.AsSlice(&buf) {
			child := *n.Children.Items[addr]
			if !yield(addr, child) {
				return
			}
		}
	}
}

// InsertChild inserts a child node at the specified address.
// Returns true if a child already existed at addr (overwrite case),
// false if this is a new insertion.
func (n *FastNode[V]) InsertChild(addr uint8, child any) (exists bool) {
	if p := n.Children.Items[addr]; p != nil {
		// Reuse existing *any slot to cut allocations and GC churn
		*p = child // overwrite
		return true
	}

	n.Children.Set(addr)
	n.CldCount++

	// pointer to any reduces per-slot memory for nil entries versus storing `any` directly.
	p := new(any)
	*p = child
	n.Children.Items[addr] = p

	return false
}

// DeleteChild removes the child node at the specified address.
// This operation is idempotent - removing a non-existent child is safe.
func (n *FastNode[V]) DeleteChild(addr uint8) (exists bool) {
	if n.Children.Items[addr] == nil {
		return false
	}
	n.CldCount--

	n.Children.Clear(addr)
	n.Children.Items[addr] = nil
	return true
}

// InsertPrefix adds or updates a routing entry at the specified index with the given value.
// It returns true if a prefix already existed at that index (indicating an update),
// false if this is a new insertion.
func (n *FastNode[V]) InsertPrefix(idx uint8, val V) (exists bool) {
	if exists = n.Prefixes.Test(idx); !exists {
		n.Prefixes.Set(idx)
		n.PfxCount++
	}

	// insert or update

	// To ensure allot works as intended, every unique prefix in the
	// FastNode must point to a distinct value pointer, even for identical values.
	// Using new() and assignment guarantees each inserted prefix gets its own address,
	valPtr := new(V)
	*valPtr = val

	oldValPtr := n.Prefixes.Items[idx]

	// overwrite oldValPtr with valPtr
	n.allot(idx, oldValPtr, valPtr)

	return exists
}

// GetPrefix returns the value for the given prefix index and true if it exists.
// If no prefix exists at idx, returns the zero value and false.
func (n *FastNode[V]) GetPrefix(idx uint8) (val V, exists bool) {
	if exists = n.Prefixes.Test(idx); exists {
		val = *n.Prefixes.Items[idx]
	}
	return val, exists
}

// MustGetPrefix returns the value for the given prefix index.
// Panics if no prefix exists at idx. This method should only be called
// when the caller has verified the prefix exists.
func (n *FastNode[V]) MustGetPrefix(idx uint8) V {
	return *n.Prefixes.Items[idx]
}

// AllIndices returns an iterator over all prefix entries.
// Each iteration yields the prefix index (uint8) and its associated value (V).
func (n *FastNode[V]) AllIndices() iter.Seq2[uint8, V] {
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

// DeletePrefix removes the route at the given index.
// Returns true if the prefix existed, otherwise false.
func (n *FastNode[V]) DeletePrefix(idx uint8) (exists bool) {
	if exists = n.Prefixes.Test(idx); !exists {
		// Route entry doesn't exist
		return exists
	}
	n.PfxCount--

	valPtr := n.Prefixes.Items[idx]
	parentValPtr := n.Prefixes.Items[idx>>1]

	// delete -> overwrite valPtr with parentValPtr
	n.allot(idx, valPtr, parentValPtr)

	n.Prefixes.Clear(idx)
	return true
}

// Contains returns true if the given index has any matching longest-prefix
// in the current node's prefix table.
//
// This function performs a presence check using the ART algorithm's
// hierarchical prefix structure. It tests whether any ancestor prefix
// exists for the given index by probing the slot at idx (children inherit
// ancestor pointers via allot).
func (n *FastNode[V]) Contains(idx uint8) (ok bool) {
	return n.Prefixes.Items[idx] != nil
}

// Lookup performs a longest-prefix match (LPM) Lookup for the given index
// within the current node's prefix table in O(1).
//
// The function returns the matched value and true if a matching prefix exists;
// otherwise, it returns the zero value and false. The Lookup uses the ART
// algorithm's hierarchical structure to find the most specific
// matching prefix.
func (n *FastNode[V]) Lookup(idx uint8) (val V, ok bool) {
	if valPtr := n.Prefixes.Items[idx]; valPtr != nil {
		return *valPtr, true
	}
	return val, ok
}

// LookupIdx performs a longest-prefix match (LPM) lookup for the given index (idx)
// within the 8-bit stride-based prefix table at this trie depth.
//
// The function returns the matched base index, associated value, and true if a
// matching prefix exists at this level; otherwise, ok is false.
//
// Its semantics are identical to [node.LookupIdx].
func (n *FastNode[V]) LookupIdx(idx uint8) (top uint8, val V, ok bool) {
	// top is the idx of the longest-prefix-match
	if top, ok = n.Prefixes.IntersectionTop(&lpm.LookupTbl[idx]); ok {
		return top, *n.Prefixes.Items[top], true
	}
	return top, val, ok
}

// allot updates entries whose stored valPtr matches oldValPtr, in the
// subtree rooted at idx. Matching entries have their stored oldValPtr set to
// valPtr, and their value set to val.
//
// allot is the core of the ART algorithm, enabling efficient insertion/deletion
// while preserving very fast lookups.
//
// Example of (uninterrupted) allotment sequence:
//
//	addr/bits: 0/5 -> {0/5, 0/6, 4/6, 0/7, 2/7, 4/7, 6/7}
//	                    ╭────╮╭─────────┬────╮
//	       idx: 32 ->  32    64   65   128  129 130  131
//	                    ╰─────────╯╰─────────────┴────╯
//
// Using an iterative form ensures better inlining opportunities.
func (n *FastNode[V]) allot(idx uint8, oldValPtr, valPtr *V) {
	// iteration with stack instead of recursion
	stack := make([]uint8, 0, 256)

	// start idx
	stack = append(stack, idx)

	for i := 0; i < len(stack); i++ {
		idx = stack[i]

		// stop this allot path, idx already points to a more specific route.
		if n.Prefixes.Items[idx] != oldValPtr {
			continue // take next path from stack
		}

		// overwrite
		n.Prefixes.Items[idx] = valPtr

		// max idx is 255, so stop the duplication at 128 and above
		if idx >= 128 {
			continue
		}

		// child nodes, it's a complete binary tree
		// left:  idx*2
		// right: (idx*2)+1
		stack = append(stack, idx<<1, (idx<<1)+1)
	}
}

// CloneFlat returns a shallow copy of the current FastNode[V],
// Its semantics are identical to [bartNode.CloneFlat] but the
// implementation is more complex.
func (n *FastNode[V]) CloneFlat(cloneFn value.CloneFunc[V]) *FastNode[V] {
	if n == nil {
		return nil
	}

	c := new(FastNode[V])
	if n.IsEmpty() {
		return c
	}

	// Copy counters and bitsets (by value).
	c.PfxCount = n.PfxCount
	c.CldCount = n.CldCount
	c.Prefixes.BitSet256 = n.Prefixes.BitSet256
	c.Children.BitSet256 = n.Children.BitSet256

	// it's a clone of the prefixes ...
	// but the allot algorithm makes it more difficult
	// see also insertPrefix
	for idx, val := range n.AllIndices() {
		newValPtr := new(V)

		if cloneFn == nil {
			*newValPtr = val // just copy the value
		} else {
			*newValPtr = cloneFn(val) // clone the value
		}

		oldValPtr := c.Prefixes.Items[idx] // likely nil initially
		c.allot(idx, oldValPtr, newValPtr)
	}

	// flat clone of the children
	for addr, kidAny := range n.AllChildren() {
		switch kid := kidAny.(type) {
		case *FastNode[V]:
			// link with new *any pointer
			c.Children.Items[addr] = &kidAny

		case *LeafNode[V]:
			leafAny := any(kid.CloneLeaf(cloneFn))
			c.Children.Items[addr] = &leafAny

		case *FringeNode[V]:
			fringeAny := any(kid.CloneFringe(cloneFn))
			c.Children.Items[addr] = &fringeAny

		default:
			panic("logic error, wrong node type")
		}
	}

	return c
}

// CloneRec performs a recursive deep copy of the FastNode[V] and all its descendants.
// Its semantics are identical to [bartNode.cloneRec].
func (n *FastNode[V]) CloneRec(cloneFn value.CloneFunc[V]) *FastNode[V] {
	if n == nil {
		return nil
	}

	// Perform a flat clone of the current node.
	c := n.CloneFlat(cloneFn)

	// Recursively clone all child nodes of type *FastNode[V]
	for addr, kidAny := range c.AllChildren() {
		switch kid := kidAny.(type) {
		case *FastNode[V]:
			nodeAny := any(kid.CloneRec(cloneFn))
			c.Children.Items[addr] = &nodeAny
		}
	}

	return c
}
