// Code generated from file "commonmethods_tmpl.go"; DO NOT EDIT.

// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/gaissmai/bart/internal/allot"
	"github.com/gaissmai/bart/internal/art"
	"github.com/gaissmai/bart/internal/value"
)

// Insert inserts a network prefix and its associated value into the
// trie starting at the specified byte depth.
//
// The function traverses the prefix address from the given depth and inserts
// the value either directly into the node's prefix table or as a compressed
// leaf or fringe node. If a conflicting leaf or fringe exists, it creates
// a new intermediate node to accommodate both entries.
//
// Parameters:
//   - pfx: The network prefix to insert (must be in canonical form)
//   - val: The value to associate with the prefix
//   - depth: The current depth in the trie (0-based byte index)
//
// Returns true if a prefix already existed and was updated, false for new insertions.
func (n *FastNode[V]) Insert(pfx netip.Prefix, val V, depth int) (exists bool) {
	ip := pfx.Addr() // the pfx must be in canonical form
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// find the proper trie node to insert prefix
	// start with prefix octet at depth
	for ; depth < len(octets); depth++ {
		octet := octets[depth]

		// last masked octet: insert/override prefix/val into node
		if depth == lastOctetPlusOne {
			return n.InsertPrefix(art.PfxToIdx(octet, lastBits), val)
		}

		// reached end of trie path ...
		if !n.Children.Test(octet) {
			// insert prefix path compressed as leaf or fringe
			if IsFringe(depth, pfx) {
				return n.InsertChild(octet, NewFringeNode(val))
			}
			return n.InsertChild(octet, NewLeafNode(pfx, val))
		}

		// ... or descend down the trie
		kid := n.MustGetChild(octet)

		// kid is node or leaf at addr
		switch kid := kid.(type) {
		case *FastNode[V]:
			n = kid // descend down to next trie level

		case *LeafNode[V]:
			// reached a path compressed prefix
			// override value in slot if prefixes are equal
			if kid.Prefix == pfx {
				kid.Value = val
				// exists
				return true
			}

			// create new node
			// push the leaf down
			// insert new child at current leaf position (addr)
			// descend down, replace n with new child
			newNode := new(FastNode[V])
			newNode.Insert(kid.Prefix, kid.Value, depth+1)

			n.InsertChild(octet, newNode)
			n = newNode

		case *FringeNode[V]:
			// reached a path compressed fringe
			// override value in slot if pfx is a fringe
			if IsFringe(depth, pfx) {
				kid.Value = val
				// exists
				return true
			}

			// create new node
			// push the fringe down, it becomes a default route (idx=1)
			// insert new child at current leaf position (addr)
			// descend down, replace n with new child
			newNode := new(FastNode[V])
			newNode.InsertPrefix(1, kid.Value)

			n.InsertChild(octet, newNode)
			n = newNode

		default:
			panic("logic error, wrong node type")
		}
	}
	panic("unreachable")
}

// InsertPersist is similar to insert but the receiver isn't modified.
// Assumes the caller has pre-cloned the root (COW). It clones the
// internal nodes along the descent path before mutating them.
func (n *FastNode[V]) InsertPersist(cloneFn value.CloneFunc[V], pfx netip.Prefix, val V, depth int) (exists bool) {
	ip := pfx.Addr() // the pfx must be in canonical form
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// find the proper trie node to insert prefix
	// start with prefix octet at depth
	for ; depth < len(octets); depth++ {
		octet := octets[depth]

		// last masked octet: insert/override prefix/val into node
		if depth == lastOctetPlusOne {
			return n.InsertPrefix(art.PfxToIdx(octet, lastBits), val)
		}

		// reached end of trie path ...
		if !n.Children.Test(octet) {
			// insert prefix path compressed as leaf or fringe
			if IsFringe(depth, pfx) {
				return n.InsertChild(octet, NewFringeNode(val))
			}
			return n.InsertChild(octet, NewLeafNode(pfx, val))
		}

		// ... or descend down the trie
		kid := n.MustGetChild(octet)

		// kid is node or leaf at addr
		switch kid := kid.(type) {
		case *FastNode[V]:
			// clone the traversed path

			// kid points now to cloned kid
			kid = kid.CloneFlat(cloneFn)

			// replace kid with clone
			n.InsertChild(octet, kid)

			n = kid
			continue // descend down to next trie level

		case *LeafNode[V]:
			// reached a path compressed prefix
			// override value in slot if prefixes are equal
			if kid.Prefix == pfx {
				kid.Value = val
				// exists
				return true
			}

			// create new node
			// push the leaf down
			// insert new child at current leaf position (addr)
			// descend down, replace n with new child
			newNode := new(FastNode[V])
			newNode.Insert(kid.Prefix, kid.Value, depth+1)

			n.InsertChild(octet, newNode)
			n = newNode

		case *FringeNode[V]:
			// reached a path compressed fringe
			// override value in slot if pfx is a fringe
			if IsFringe(depth, pfx) {
				kid.Value = val
				// exists
				return true
			}

			// create new node
			// push the fringe down, it becomes a default route (idx=1)
			// insert new child at current leaf position (addr)
			// descend down, replace n with new child
			newNode := new(FastNode[V])
			newNode.InsertPrefix(1, kid.Value)

			n.InsertChild(octet, newNode)
			n = newNode

		default:
			panic("logic error, wrong node type")
		}

	}

	panic("unreachable")
}

// PurgeAndCompress performs bottom-up compression of the trie.
//
// The function unwinds the provided stack of parent nodes, checking each level
// for compression opportunities based on child and prefix count.
// It may convert:
//   - Nodes with a single prefix into leaf one level above.
//   - Nodes with a single leaf or fringe into leaf one level above.
//
// Parameters:
//   - stack: Array of parent nodes to process during unwinding
//   - octets: The path of octets taken to reach the current position
//   - is4: True for IPv4 processing, false for IPv6
func (n *FastNode[V]) PurgeAndCompress(stack []*FastNode[V], octets []uint8, is4 bool) {
	// unwind the stack
	for depth := len(stack) - 1; depth >= 0; depth-- {
		parent := stack[depth]
		octet := octets[depth]

		pfxCount := n.PrefixCount()
		childCount := n.ChildCount()

		if pfxCount+childCount > 1 {
			return
		}

		switch {
		case childCount == 1:
			singleAddr, _ := n.Children.FirstSet() // single addr must be first bit set
			anyKid := n.MustGetChild(singleAddr)

			switch kid := anyKid.(type) {
			case *FastNode[V]:
				// fast exit, we are at an intermediate path node
				// no further delete/compress upwards the stack is possible
				return
			case *LeafNode[V]:
				// just one leaf, delete this node and reinsert the leaf above
				parent.DeleteChild(octet)

				// ... (re)insert the leaf at parents depth
				parent.Insert(kid.Prefix, kid.Value, depth)
			case *FringeNode[V]:
				// just one fringe, delete this node and reinsert the fringe as leaf above
				parent.DeleteChild(octet)

				// rebuild the prefix with octets, depth, ip version and addr
				// depth is the parent's depth, so add +1 here for the kid
				// lastOctet in cidrForFringe is the only addr (singleAddr)
				fringePfx := CidrForFringe(octets, depth+1, is4, singleAddr)

				// ... (re)reinsert prefix/value at parents depth
				parent.Insert(fringePfx, kid.Value, depth)
			}

		case pfxCount == 1:
			// just one prefix, delete this node and reinsert the idx as leaf above
			parent.DeleteChild(octet)

			// get prefix back from idx ...
			idx, _ := n.Prefixes.FirstSet() // single idx must be first bit set
			val := n.MustGetPrefix(idx)

			// ... and octet path
			path := StridePath{}
			copy(path[:], octets)

			// depth is the parent's depth, so add +1 here for the kid
			pfx := CidrFromPath(path, depth+1, is4, idx)

			// ... (re)insert prefix/value at parents depth
			parent.Insert(pfx, val, depth)
		}

		// climb up the stack
		n = parent
	}
}

// Delete deletes the prefix and returns true if the prefix existed,
// or false otherwise. The prefix must be in canonical form.
func (n *FastNode[V]) Delete(pfx netip.Prefix) (exists bool) {
	// invariant, prefix must be masked

	// values derived from pfx
	ip := pfx.Addr()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// record the nodes on the path to the deleted node, needed to purge
	// and/or path compress nodes after the deletion of a prefix
	stack := [MaxTreeDepth]*FastNode[V]{}

	// find the trie node
	for depth, octet := range octets {
		depth = depth & DepthMask // BCE, Delete must be fast

		// push current node on stack for path recording
		stack[depth] = n

		// Last “octet” from prefix, update/insert prefix into node.
		// Note: For /32 and /128, depth never reaches lastOctetPlusOne (4/16),
		// so those are handled below via the fringe/leaf path.
		if depth == lastOctetPlusOne {
			// try to delete prefix in trie node
			if exists = n.DeletePrefix(art.PfxToIdx(octet, lastBits)); !exists {
				return false
			}

			// remove now-empty nodes and re-path-compress upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true
		}

		if !n.Children.Test(octet) {
			return false
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *FastNode[V]:
			n = kid // descend down to next trie level

		case *FringeNode[V]:
			// if pfx is no fringe at this depth, fast exit
			if !IsFringe(depth, pfx) {
				return false
			}

			// pfx is fringe at depth, delete fringe
			n.DeleteChild(octet)

			// remove now-empty nodes and re-path-compress upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)

			return true

		case *LeafNode[V]:
			// Attention: pfx must be masked to be comparable!
			if kid.Prefix != pfx {
				return false
			}

			// prefix is equal leaf, delete leaf
			n.DeleteChild(octet)

			// remove now-empty nodes and re-path-compress upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)

			return true

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// DeletePersist is similar to delete but does not mutate the original trie.
// Assumes the caller has pre-cloned the root (COW). It clones the
// internal nodes along the descent path before mutating them.
func (n *FastNode[V]) DeletePersist(cloneFn value.CloneFunc[V], pfx netip.Prefix) (exists bool) {
	ip := pfx.Addr() // the pfx must be in canonical form
	is4 := ip.Is4()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// Stack to keep track of cloned nodes along the path,
	// needed for purge and path compression after delete.
	stack := [MaxTreeDepth]*FastNode[V]{}

	// Traverse the trie to locate the prefix to delete.
	for depth, octet := range octets {
		// Keep track of the cloned node at current depth.
		stack[depth] = n

		if depth == lastOctetPlusOne {
			// Attempt to delete the prefix from the node's prefixes.
			if exists = n.DeletePrefix(art.PfxToIdx(octet, lastBits)); !exists {
				// Prefix not found, nothing deleted.
				return false
			}

			// After deletion, purge nodes and compress the path if needed.
			n.PurgeAndCompress(stack[:depth], octets, is4)

			return true
		}

		addr := octet

		// If child node doesn't exist, no prefix to delete.
		if !n.Children.Test(addr) {
			return false
		}

		// Fetch child node at current address.
		kid := n.MustGetChild(addr)

		switch kid := kid.(type) {
		case *FastNode[V]:
			// Clone the internal node for copy-on-write.
			kid = kid.CloneFlat(cloneFn)

			// Replace child with cloned node.
			n.InsertChild(addr, kid)

			// Descend to cloned child node.
			n = kid
			continue

		case *FringeNode[V]:
			// Reached a path compressed fringe.
			if !IsFringe(depth, pfx) {
				// Prefix to delete not found here.
				return false
			}

			// Delete the fringe node.
			n.DeleteChild(addr)

			// Purge and compress affected path.
			n.PurgeAndCompress(stack[:depth], octets, is4)

			return true

		case *LeafNode[V]:
			// Reached a path compressed leaf node.
			if kid.Prefix != pfx {
				// Leaf prefix does not match; nothing to delete.
				return false
			}

			// Delete leaf node.
			n.DeleteChild(addr)

			// Purge and compress affected path.
			n.PurgeAndCompress(stack[:depth], octets, is4)

			return true

		default:
			// Unexpected node type indicates a logic error.
			panic("logic error, wrong node type")
		}
	}

	// Should never happen: traversal always returns or panics inside loop.
	panic("unreachable")
}

// Get retrieves the value associated with the given network prefix.
// Returns the stored value and true if the prefix exists in this node,
// zero value and false if the prefix is not found.
//
// Parameters:
//   - pfx: The network prefix to look up (must be in canonical form)
//
// Returns:
//   - val: The value associated with the prefix (zero value if not found)
//   - exists: True if the prefix was found, false otherwise
func (n *FastNode[V]) Get(pfx netip.Prefix) (val V, exists bool) {
	// invariant, prefix must be masked

	// values derived from pfx
	ip := pfx.Addr()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// find the trie node
	for depth, octet := range octets {
		if depth == lastOctetPlusOne {
			return n.GetPrefix(art.PfxToIdx(octet, lastBits))
		}

		kidAny, ok := n.GetChild(octet)
		if !ok {
			return val, false
		}

		// kid is node or leaf or fringe at octet
		switch kid := kidAny.(type) {
		case *FastNode[V]:
			n = kid // descend down to next trie level

		case *FringeNode[V]:
			// reached a path compressed fringe, stop traversing
			if IsFringe(depth, pfx) {
				return kid.Value, true
			}
			return val, false

		case *LeafNode[V]:
			// reached a path compressed prefix, stop traversing
			if kid.Prefix == pfx {
				return kid.Value, true
			}
			return val, false

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// Modify performs an in-place modification of a prefix using the provided callback function.
// The callback receives the current value (if found) and existence flag, and returns
// a new value and deletion flag.
//
// modify returns the size delta (-1, 0, +1).
// This method handles path traversal, node creation for new paths, and automatic
// purge/compress operations after deletions.
//
// Parameters:
//   - pfx: The network prefix to modify (must be in canonical form)
//   - cb: Callback function that receives (currentValue, exists) and returns (newValue, deleteFlag)
//
// Returns:
//   - delta: Size change (-1 for delete, 0 for update/noop, +1 for insert)
func (n *FastNode[V]) Modify(pfx netip.Prefix, cb func(val V, found bool) (_ V, del bool)) (delta int) {
	var zero V

	ip := pfx.Addr()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// record the nodes on the path to the deleted node, needed to purge
	// and/or path compress nodes after the deletion of a prefix
	stack := [MaxTreeDepth]*FastNode[V]{}

	// find the proper trie node to update prefix
	for depth, octet := range octets {
		depth = depth & DepthMask // BCE

		// push current node on stack for path recording
		stack[depth] = n

		// Last “octet” from prefix, update/insert prefix into node.
		// Note: For /32 and /128, depth never reaches lastOctetPlusOne (4/16),
		// so those are handled below via the fringe/leaf path.
		if depth == lastOctetPlusOne {
			idx := art.PfxToIdx(octet, lastBits)

			oldVal, existed := n.GetPrefix(idx)
			newVal, del := cb(oldVal, existed)

			// update size if necessary
			switch {
			case !existed && del: // no-op
				return 0

			case existed && del: // delete
				n.DeletePrefix(idx)
				// remove now-empty nodes and re-path-compress upwards
				n.PurgeAndCompress(stack[:depth], octets, is4)
				return -1

			case !existed: // insert
				n.InsertPrefix(idx, newVal)
				return 1

			case existed: // update
				n.InsertPrefix(idx, newVal)
				return 0

			default:
				panic("unreachable")
			}

		}

		// go down in tight loop to last octet
		if !n.Children.Test(octet) {
			// insert prefix path compressed

			newVal, del := cb(zero, false)
			if del {
				return 0
			}

			// insert
			if IsFringe(depth, pfx) {
				n.InsertChild(octet, NewFringeNode(newVal))
			} else {
				n.InsertChild(octet, NewLeafNode(pfx, newVal))
			}

			return 1
		}

		// n.children.Test(octet) == true
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *FastNode[V]:
			n = kid // descend down to next trie level
			continue

		case *LeafNode[V]:
			oldVal := kid.Value

			// update existing value if prefixes are equal
			if kid.Prefix == pfx {
				newVal, del := cb(oldVal, true)

				if !del {
					kid.Value = newVal
					return 0
				}

				// delete
				n.DeleteChild(octet)

				// remove now-empty nodes and re-path-compress upwards
				n.PurgeAndCompress(stack[:depth], octets, is4)

				return -1
			}

			// stop if this is a no-op for zero values
			newVal, del := cb(zero, false)
			if del {
				return 0
			}

			// create new node
			// insert new child at current leaf position (octet)
			newNode := new(FastNode[V])
			n.InsertChild(octet, newNode)

			// push the leaf down
			// insert pfx with newVal in new node
			newNode.Insert(kid.Prefix, kid.Value, depth+1)
			newNode.Insert(pfx, newVal, depth+1)

			return 1

		case *FringeNode[V]:
			// update existing value if prefix is fringe
			if IsFringe(depth, pfx) {
				newVal, del := cb(kid.Value, true)
				if !del {
					kid.Value = newVal
					return 0
				}

				// delete
				n.DeleteChild(octet)

				// remove now-empty nodes and re-path-compress upwards
				n.PurgeAndCompress(stack[:depth], octets, is4)

				return -1
			}

			// stop if this is a no-op for zero values
			newVal, del := cb(zero, false)
			if del {
				return 0
			}

			// create new node
			// insert new child at current leaf position (octet)
			newNode := new(FastNode[V])
			n.InsertChild(octet, newNode)

			// push the fringe down, it becomes a default route (idx=1)
			// insert pfx with newVal in new node
			newNode.InsertPrefix(1, kid.Value)
			newNode.Insert(pfx, newVal, depth+1)

			return 1

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// EqualRec performs recursive structural equality comparison between two nodes.
// Compares prefix and child bitsets, then recursively compares all stored values
// and child nodes. Returns true if the nodes and their entire subtrees are
// structurally and semantically identical, false otherwise.
//
// The comparison handles different node types (internal nodes, leafNodes, fringeNodes)
// and uses the equal function for value comparisons to support custom equality logic.
func (n *FastNode[V]) EqualRec(o *FastNode[V]) bool {
	if n == nil || o == nil {
		return n == o
	}
	if n == o {
		return true
	}

	if n.Prefixes.BitSet256 != o.Prefixes.BitSet256 {
		return false
	}

	if n.Children.BitSet256 != o.Children.BitSet256 {
		return false
	}

	for idx, nVal := range n.AllIndices() {
		oVal := o.MustGetPrefix(idx) // mustGet is ok, bitsets are equal
		if !value.Equal(nVal, oVal) {
			return false
		}
	}

	for addr, nKid := range n.AllChildren() {
		oKid := o.MustGetChild(addr) // mustGet is ok, bitsets are equal

		switch nKid := nKid.(type) {
		case *FastNode[V]:
			// oKid must also be a node
			oKid, ok := oKid.(*FastNode[V])
			if !ok {
				return false
			}

			// compare rec-descent
			if !nKid.EqualRec(oKid) {
				return false
			}

		case *LeafNode[V]:
			// oKid must also be a leaf
			oKid, ok := oKid.(*LeafNode[V])
			if !ok {
				return false
			}

			// compare prefixes
			if nKid.Prefix != oKid.Prefix {
				return false
			}

			// compare values
			if !value.Equal(nKid.Value, oKid.Value) {
				return false
			}

		case *FringeNode[V]:
			// oKid must also be a fringe
			oKid, ok := oKid.(*FringeNode[V])
			if !ok {
				return false
			}

			// compare values
			if !value.Equal(nKid.Value, oKid.Value) {
				return false
			}

		default:
			panic("logic error, wrong node type")
		}
	}

	return true
}

// DumpRec recursively descends the trie rooted at n and writes a human-readable
// representation of each visited node to w.
//
// It returns immediately if n is nil or empty. For each visited internal node
// it calls dump to write the node's representation, then iterates its child
// addresses and recurses into children that implement nodeDumper[V] (internal
// subnodes). The path slice and depth together represent the byte-wise path
// from the root to the current node; depth is incremented for each recursion.
// The is4 flag controls IPv4/IPv6 formatting used by dump.
func (n *FastNode[V]) DumpRec(w io.Writer, path StridePath, depth int, is4 bool) {
	if n == nil || n.IsEmpty() {
		return
	}

	// dump this node
	n.dump(w, path, depth, is4)

	// node may have children, rec-descent down
	for addr, child := range n.AllChildren() {
		if kid, ok := child.(*FastNode[V]); ok {
			path[depth] = addr
			kid.DumpRec(w, path, depth+1, is4)
		}
	}
}

// dump writes a human-readable representation of the node to `w`.
// It prints the node type, depth, formatted path (IPv4 vs IPv6 controlled by `is4`),
// and bit count, followed by any stored prefixes (and their values when applicable),
// the set of child octets, and any path-compressed leaves or fringe entries.
func (n *FastNode[V]) dump(w io.Writer, path StridePath, depth int, is4 bool) {
	bits := depth * strideLen
	indent := strings.Repeat(".", depth)

	// printing values if V is not zero-sized
	printValues := !value.IsZST[V]()

	// node type with depth and octet path and bits.
	fmt.Fprintf(w, "\n%s[%s] depth:  %d path: [%s] / %d\n",
		indent, n.hasType(), depth, ipStridePath(path, depth, is4), bits)

	if nPfxCount := n.PrefixCount(); nPfxCount != 0 {
		var buf [256]uint8
		allIndices := n.Prefixes.AsSlice(&buf)

		// print the baseIndices for this node.
		fmt.Fprintf(w, "%sindexs(#%d): %v\n", indent, nPfxCount, allIndices)

		// print the prefixes for this node
		fmt.Fprintf(w, "%sprefxs(#%d):", indent, nPfxCount)

		for _, idx := range allIndices {
			pfx := CidrFromPath(path, depth, is4, idx)
			fmt.Fprintf(w, " %s", pfx)
		}

		fmt.Fprintln(w)

		// skip printing values if V is zero-sized
		if printValues {

			// print the values for this node
			fmt.Fprintf(w, "%svalues(#%d):", indent, nPfxCount)

			for _, idx := range allIndices {
				val := n.MustGetPrefix(idx)
				fmt.Fprintf(w, " %#v", val)
			}

			fmt.Fprintln(w)
		}
	}

	if cc := n.ChildCount(); cc != 0 {
		allAddrs := make([]uint8, 0, cc)
		childAddrs := make([]uint8, 0, cc)
		leafAddrs := make([]uint8, 0, cc)
		fringeAddrs := make([]uint8, 0, cc)

		// the node has recursive child nodes or path-compressed leaves
		for addr, child := range n.AllChildren() {
			allAddrs = append(allAddrs, addr)

			switch child.(type) {
			case *FastNode[V]:
				childAddrs = append(childAddrs, addr)
				continue

			case *FringeNode[V]:
				fringeAddrs = append(fringeAddrs, addr)

			case *LeafNode[V]:
				leafAddrs = append(leafAddrs, addr)

			default:
				panic("logic error, wrong node type")
			}
		}

		// print the children for this node.
		fmt.Fprintf(w, "%soctets(#%d): %v\n", indent, len(allAddrs), allAddrs)

		if leafCount := len(leafAddrs); leafCount > 0 {
			// print the pathcomp prefixes for this node
			fmt.Fprintf(w, "%sleaves(#%d):", indent, leafCount)

			for _, addr := range leafAddrs {
				kid := n.MustGetChild(addr).(*LeafNode[V])

				// skip printing values if V is zero-sized
				if printValues {
					fmt.Fprintf(w, " %s:{%s, %v}", addrFmt(addr, is4), kid.Prefix, kid.Value)
				} else {
					fmt.Fprintf(w, " %s:{%s}", addrFmt(addr, is4), kid.Prefix)
				}
			}

			fmt.Fprintln(w)
		}

		if fringeCount := len(fringeAddrs); fringeCount > 0 {
			// print the pathcomp prefixes for this node
			fmt.Fprintf(w, "%sfringe(#%d):", indent, fringeCount)

			for _, addr := range fringeAddrs {
				fringePfx := CidrForFringe(path[:], depth, is4, addr)

				kid := n.MustGetChild(addr).(*FringeNode[V])

				// skip printing values if V is zero-sized
				if printValues {
					fmt.Fprintf(w, " %s:{%s, %v}", addrFmt(addr, is4), fringePfx, kid.Value)
				} else {
					fmt.Fprintf(w, " %s:{%s}", addrFmt(addr, is4), fringePfx)
				}
			}

			fmt.Fprintln(w)
		}

		if childCount := len(childAddrs); childCount > 0 {
			// print the next child
			fmt.Fprintf(w, "%schilds(#%d):", indent, childCount)

			for _, addr := range childAddrs {
				fmt.Fprintf(w, " %s", addrFmt(addr, is4))
			}

			fmt.Fprintln(w)
		}

	}
}

// DumpString traverses the trie to the node at the specified depth along the given
// octet path and returns its string representation via Dump.
//
// If the path is invalid or encounters an unexpected node type during traversal,
// it returns an error message string instead.
//
// Parameters:
//   - octets: The path of octets to follow from the root
//   - depth: Target depth to reach before dumping (0-based byte index)
//   - is4: True for IPv4 formatting, false for IPv6
//
// Returns a formatted string representation of the target node or an error message.
func (n *FastNode[V]) DumpString(octets []uint8, depth int, is4 bool) string {
	path := StridePath{}
	copy(path[:], octets)

	buf := new(strings.Builder)
	for i := range depth {
		anyKid, ok := n.GetChild(path[i])
		if !ok {
			return fmt.Sprintf("ERROR: kid for %v[%d] is NOT set in node\n", octets, i)
		}

		kid, ok := anyKid.(*FastNode[V])
		if !ok {
			return fmt.Sprintf("ERROR: kid for %v[%d] is NO %s\n", octets, i, "FastNode[V]")
		}

		// traverse
		n = kid
	}

	n.dump(buf, path, depth, is4)
	return buf.String()
}

// hasType classifies the given node into one of the nodeType values.
//
// It inspects immediate statistics (prefix count, child count, node, leaf and
// fringe counts) for the node and returns:
//   - nullNode: no prefixes and no children
//   - stopNode: has children but no subnodes (nodes == 0)
//   - halfNode: contains at least one leaf or fringe and also has subnodes, but
//     no prefixes
//   - fullNode: has prefixes or leaves/fringes and also has subnodes
//   - pathNode: has subnodes only (no prefixes, leaves, or fringes)
//
// The order of these checks is significant to ensure the correct classification.
func (n *FastNode[V]) hasType() nodeType {
	s := n.Stats()

	// the order is important
	switch {
	case s.Prefixes == 0 && s.Children == 0:
		return nullNode
	case s.SubNodes == 0:
		return stopNode
	case (s.Leaves > 0 || s.Fringes > 0) && s.SubNodes > 0 && s.Prefixes == 0:
		return halfNode
	case (s.Prefixes > 0 || s.Leaves > 0 || s.Fringes > 0) && s.SubNodes > 0:
		return fullNode
	case (s.Prefixes == 0 && s.Leaves == 0 && s.Fringes == 0) && s.SubNodes > 0:
		return pathNode
	default:
		panic(fmt.Sprintf("UNREACHABLE: pfx: %d, chld: %d, node: %d, leaf: %d, fringe: %d",
			s.Prefixes, s.Children, s.SubNodes, s.Leaves, s.Fringes))
	}
}

// Stats returns immediate statistics for n: counts of prefixes and children,
// and a classification of each child into nodes, leaves, or fringes.
// It inspects only the direct children of n (not the whole subtree).
// Panics if a child has an unexpected concrete type.
func (n *FastNode[V]) Stats() (s StatsT) {
	s.Prefixes = n.PrefixCount()
	s.Children = n.ChildCount()

	for _, child := range n.AllChildren() {
		switch child.(type) {
		case *FastNode[V]:
			s.SubNodes++

		case *FringeNode[V]:
			s.Fringes++

		case *LeafNode[V]:
			s.Leaves++

		default:
			panic("logic error, wrong node type")
		}
	}

	return s
}

// StatsRec returns aggregated statistics for the subtree rooted at n.
//
// It walks the node tree recursively and sums immediate counts (prefixes and
// child slots) plus the number of nodes, leaves, and fringe nodes in the
// subtree. If n is nil or empty, a zeroed stats is returned. The returned
// stats.nodes includes the current node. The function will panic if a child
// has an unexpected concrete type.
func (n *FastNode[V]) StatsRec() (s StatsT) {
	if n == nil || n.IsEmpty() {
		return s
	}

	s.Prefixes = n.PrefixCount()
	s.Children = n.ChildCount()
	s.SubNodes = 1 // this node
	s.Leaves = 0
	s.Fringes = 0

	for _, child := range n.AllChildren() {
		switch kid := child.(type) {
		case *FastNode[V]:
			// rec-descent
			rs := kid.StatsRec()

			s.Prefixes += rs.Prefixes
			s.Children += rs.Children
			s.SubNodes += rs.SubNodes
			s.Leaves += rs.Leaves
			s.Fringes += rs.Fringes

		case *FringeNode[V]:
			s.Fringes++

		case *LeafNode[V]:
			s.Leaves++

		default:
			panic("logic error, wrong node type")
		}
	}

	return s
}

// FprintRec recursively prints a hierarchical CIDR tree representation
// starting from this node to the provided writer. The output shows the
// routing table structure in human-readable format for debugging and analysis.
func (n *FastNode[V]) FprintRec(w io.Writer, parent TrieItem[V], pad string) error {
	// recursion stop condition
	if n == nil || n.IsEmpty() {
		return nil
	}

	// get direct covered childs for this parent ...
	directItems := n.DirectItemsRec(parent.Idx, parent.Path, parent.Depth, parent.Is4)

	// sort them by netip.Prefix, not by baseIndex
	slices.SortFunc(directItems, func(a, b TrieItem[V]) int {
		return CmpPrefix(a.Cidr, b.Cidr)
	})

	// printing values if V is not zero-sized
	printValues := !value.IsZST[V]()

	// for all direct item under this node ...
	for i, item := range directItems {
		// symbols used in tree
		glyph := "├─ "
		space := "│  "

		// ... treat last kid special
		if i == len(directItems)-1 {
			glyph = "└─ "
			space = "   "
		}

		var err error
		// val is the empty struct, don't print it
		if printValues {
			_, err = fmt.Fprintf(w, "%s%s (%v)\n", pad+glyph, item.Cidr, item.Val)
		} else {
			// skip printing values if V is zero-sized
			_, err = fmt.Fprintf(w, "%s%s\n", pad+glyph, item.Cidr)
		}

		if err != nil {
			return err
		}

		// rec-descent with this item as parent
		nextNode, _ := item.Node.(*FastNode[V])
		if err = nextNode.FprintRec(w, item, pad+space); err != nil {
			return err
		}
	}

	return nil
}

// DirectItemsRec, returns the direct covered items by parent.
// It's a complex recursive function, you have to know the data structure
// by heart to understand this function!
func (n *FastNode[V]) DirectItemsRec(parentIdx uint8, path StridePath, depth int, is4 bool) (directItems []TrieItem[V]) {
	// recursion stop condition
	if n == nil || n.IsEmpty() {
		return nil
	}

	// prefixes:
	// for all idx's (prefixes mapped by baseIndex) in this node
	// do a longest-prefix-match
	for idx, val := range n.AllIndices() {
		// tricky part, skip self
		// test with next possible lpm (idx>>1), it's a complete binary tree
		nextIdx := idx >> 1

		// fast skip, lpm not possible
		if nextIdx < parentIdx {
			continue
		}

		// do a longest-prefix-match
		lpm, _, _ := n.LookupIdx(nextIdx)

		// be aware, 0 is here a possible value for parentIdx and lpm (if not found)
		if lpm == parentIdx {
			// prefix is directly covered by parent

			item := TrieItem[V]{
				Node:  n,
				Is4:   is4,
				Path:  path,
				Depth: depth,
				Idx:   idx,
				// get the prefix back from trie
				Cidr: CidrFromPath(path, depth, is4, idx),
				Val:  val,
			}

			directItems = append(directItems, item)
		}
	}

	// children:
	for addr, child := range n.AllChildren() {
		hostIdx := art.OctetToIdx(addr)

		// do a longest-prefix-match
		lpm, _, _ := n.LookupIdx(hostIdx)

		// be aware, 0 is here a possible value for parentIdx and lpm (if not found)
		if lpm == parentIdx {
			// child is directly covered by parent
			switch kid := child.(type) {
			case *FastNode[V]: // traverse rec-descent, call with next child node,
				// next trie level, set parentIdx to 0, adjust path and depth
				path[depth] = addr
				directItems = append(directItems, kid.DirectItemsRec(0, path, depth+1, is4)...)

			case *LeafNode[V]: // path-compressed child, stop's recursion for this child
				item := TrieItem[V]{
					Node: nil,
					Is4:  is4,
					Cidr: kid.Prefix,
					Val:  kid.Value,
				}
				directItems = append(directItems, item)

			case *FringeNode[V]: // path-compressed fringe, stop's recursion for this child
				item := TrieItem[V]{
					Node: nil,
					Is4:  is4,
					// get the prefix back from trie
					Cidr: CidrForFringe(path[:], depth, is4, addr),
					Val:  kid.Value,
				}
				directItems = append(directItems, item)

			default:
				panic("logic error, wrong node type")
			}
		}
	}

	return directItems
}

// UnionRec recursively merges another node o into the receiver node n.
//
// All prefix and child entries from o are cloned and inserted into n.
// If a prefix already exists in n, its value is overwritten by the value from o,
// and the duplicate is counted in the return value. This count can later be used
// to update size-related metadata in the parent trie.
//
// The union handles all possible combinations of child node types (node, leaf, fringe)
// between the two nodes. Structural conflicts are resolved by creating new intermediate
// *FastNode[V] objects and pushing both children further down the trie. Leaves and fringes
// are also recursively relocated as needed to preserve prefix semantics.
//
// The merge operation is destructive on the receiver n, but leaves the source node o unchanged.
//
// Returns the number of duplicate prefixes that were overwritten during merging.
func (n *FastNode[V]) UnionRec(cloneFn value.CloneFunc[V], o *FastNode[V], depth int) (duplicates int) {
	if cloneFn == nil {
		cloneFn = value.CopyVal
	}

	buf := [256]uint8{}

	// for all prefixes in other node do ...
	for _, oIdx := range o.Prefixes.AsSlice(&buf) {
		// clone/copy the value from other node at idx
		val := o.MustGetPrefix(oIdx)
		clonedVal := cloneFn(val)

		// insert/overwrite cloned value from o into n
		if n.InsertPrefix(oIdx, clonedVal) {
			// this prefix is duplicate in n and o
			duplicates++
		}
	}

	// for all child addrs in other node do ...
	for _, addr := range o.Children.AsSlice(&buf) {
		otherChild := o.MustGetChild(addr)
		thisChild, thisExists := n.GetChild(addr)

		// Use helper function to handle all 4x3 combinations
		duplicates += n.handleMatrix(cloneFn, thisExists, thisChild, otherChild, addr, depth)
	}

	return duplicates
}

// UnionRecPersist is similar to unionRec but performs an immutable union of nodes.
func (n *FastNode[V]) UnionRecPersist(cloneFn value.CloneFunc[V], o *FastNode[V], depth int) (duplicates int) {
	if cloneFn == nil {
		cloneFn = value.CopyVal
	}

	buf := [256]uint8{}

	// for all prefixes in other node do ...
	for _, oIdx := range o.Prefixes.AsSlice(&buf) {
		// clone/copy the value from other node
		val := o.MustGetPrefix(oIdx)
		clonedVal := cloneFn(val)

		// insert/overwrite cloned value from o into n
		if exists := n.InsertPrefix(oIdx, clonedVal); exists {
			// this prefix is duplicate in n and o
			duplicates++
		}
	}

	// for all child addrs in other node do ...
	for _, addr := range o.Children.AsSlice(&buf) {
		otherChild := o.MustGetChild(addr)
		thisChild, thisExists := n.GetChild(addr)

		// Use helper function to handle all 4x3 combinations
		duplicates += n.handleMatrixPersist(cloneFn, thisExists, thisChild, otherChild, addr, depth)
	}

	return duplicates
}

// handleMatrix, 12 possible combinations to union this child and other child
//
//	THIS,   OTHER: (always clone the other kid!)
//	--------------
//	NULL,   node    <-- insert node at addr
//	NULL,   leaf    <-- insert leaf at addr
//	NULL,   fringe  <-- insert fringe at addr
//
//	node,   node    <-- union rec-descent with node
//	node,   leaf    <-- insert leaf at depth+1
//	node,   fringe  <-- insert fringe at depth+1
//
//	leaf,   node    <-- insert new node, push this leaf down, union rec-descent
//	leaf,   leaf    <-- insert new node, push both leaves down (!first check equality)
//	leaf,   fringe  <-- insert new node, push this leaf and fringe down
//
//	fringe, node    <-- insert new node, push this fringe down, union rec-descent
//	fringe, leaf    <-- insert new node, push this fringe down, insert other leaf at depth+1
//	fringe, fringe  <-- just overwrite value
func (n *FastNode[V]) handleMatrix(cloneFn value.CloneFunc[V], thisExists bool, thisChild, otherChild any, addr uint8, depth int) int {
	// Do ALL type assertions upfront - reduces line noise
	var (
		thisNode, thisIsNode     = thisChild.(*FastNode[V])
		thisLeaf, thisIsLeaf     = thisChild.(*LeafNode[V])
		thisFringe, thisIsFringe = thisChild.(*FringeNode[V])

		otherNode, otherIsNode     = otherChild.(*FastNode[V])
		otherLeaf, otherIsLeaf     = otherChild.(*LeafNode[V])
		otherFringe, otherIsFringe = otherChild.(*FringeNode[V])
	)

	// just insert cloned child at this empty slot
	if !thisExists {
		switch {
		case otherIsNode:
			n.InsertChild(addr, otherNode.CloneRec(cloneFn))
		case otherIsLeaf:
			n.InsertChild(addr, &LeafNode[V]{Prefix: otherLeaf.Prefix, Value: cloneFn(otherLeaf.Value)})
		case otherIsFringe:
			n.InsertChild(addr, &FringeNode[V]{Value: cloneFn(otherFringe.Value)})
		default:
			panic("logic error, wrong node type")
		}
		return 0
	}

	// Case 1: Special cases that DON'T need a new node

	// Special case: fringe + fringe -> just overwrite value
	if thisIsFringe && otherIsFringe {
		thisFringe.Value = cloneFn(otherFringe.Value)
		return 1
	}

	// Special case: leaf + leaf with same prefix -> just overwrite value
	if thisIsLeaf && otherIsLeaf && thisLeaf.Prefix == otherLeaf.Prefix {
		thisLeaf.Value = cloneFn(otherLeaf.Value)
		return 1
	}

	// Case 2: thisChild is already a node - insert into it, no new node needed
	if thisIsNode {
		switch {
		case otherIsNode:
			return thisNode.UnionRec(cloneFn, otherNode, depth+1)
		case otherIsLeaf:
			if thisNode.Insert(otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
				return 1
			}
			return 0
		case otherIsFringe:
			if thisNode.InsertPrefix(1, cloneFn(otherFringe.Value)) {
				return 1
			}
			return 0
		default:
			panic("logic error, wrong node type")
		}
	}

	// Case 3: All remaining cases need a new node
	// (thisChild is leaf or fringe, and we didn't hit the special cases above)

	nc := new(FastNode[V])

	// Push existing child down into new node
	switch {
	case thisIsLeaf:
		nc.Insert(thisLeaf.Prefix, thisLeaf.Value, depth+1)
	case thisIsFringe:
		nc.InsertPrefix(1, thisFringe.Value)
	default:
		panic("logic error, unexpected this child type")
	}

	// Replace child with new node
	n.InsertChild(addr, nc)

	// Now handle other child
	switch {
	case otherIsNode:
		return nc.UnionRec(cloneFn, otherNode, depth+1)
	case otherIsLeaf:
		if nc.Insert(otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
			return 1
		}
		return 0
	case otherIsFringe:
		if nc.InsertPrefix(1, cloneFn(otherFringe.Value)) {
			return 1
		}
		return 0
	default:
		panic("logic error, wrong other node type")
	}
}

// handleMatrixPersist, 12 possible combinations to union this child and other child
//
//	THIS,   OTHER: (always clone the other kid!)
//	--------------
//	NULL,   node    <-- insert node at addr
//	NULL,   leaf    <-- insert leaf at addr
//	NULL,   fringe  <-- insert fringe at addr
//
//	node,   node    <-- union rec-descent with node
//	node,   leaf    <-- insert leaf at depth+1
//	node,   fringe  <-- insert fringe at depth+1
//
//	leaf,   node    <-- insert new node, push this leaf down, union rec-descent
//	leaf,   leaf    <-- insert new node, push both leaves down (!first check equality)
//	leaf,   fringe  <-- insert new node, push this leaf and fringe down
//
//	fringe, node    <-- insert new node, push this fringe down, union rec-descent
//	fringe, leaf    <-- insert new node, push this fringe down, insert other leaf at depth+1
//	fringe, fringe  <-- just overwrite value
func (n *FastNode[V]) handleMatrixPersist(cloneFn value.CloneFunc[V], thisExists bool, thisChild, otherChild any, addr uint8, depth int) int {
	// Do ALL type assertions upfront - reduces line noise
	var (
		thisNode, thisIsNode     = thisChild.(*FastNode[V])
		thisLeaf, thisIsLeaf     = thisChild.(*LeafNode[V])
		thisFringe, thisIsFringe = thisChild.(*FringeNode[V])

		otherNode, otherIsNode     = otherChild.(*FastNode[V])
		otherLeaf, otherIsLeaf     = otherChild.(*LeafNode[V])
		otherFringe, otherIsFringe = otherChild.(*FringeNode[V])
	)

	// just insert cloned child at this empty slot
	if !thisExists {
		switch {
		case otherIsNode:
			n.InsertChild(addr, otherNode.CloneRec(cloneFn))
		case otherIsLeaf:
			n.InsertChild(addr, &LeafNode[V]{Prefix: otherLeaf.Prefix, Value: cloneFn(otherLeaf.Value)})
		case otherIsFringe:
			n.InsertChild(addr, &FringeNode[V]{Value: cloneFn(otherFringe.Value)})
		default:
			panic("logic error, wrong node type")
		}
		return 0
	}

	// Case 1: Special cases that DON'T need a new node

	// Special case: fringe + fringe -> just overwrite value
	if thisIsFringe && otherIsFringe {
		thisFringe.Value = cloneFn(otherFringe.Value)
		return 1
	}

	// Special case: leaf + leaf with same prefix -> just overwrite value
	if thisIsLeaf && otherIsLeaf && thisLeaf.Prefix == otherLeaf.Prefix {
		thisLeaf.Value = cloneFn(otherLeaf.Value)
		return 1
	}

	// Case 2: thisChild is already a node - clone this node, insert into it
	if thisIsNode {
		// CLONE the node

		// thisNode points now to cloned kid
		thisNode = thisNode.CloneFlat(cloneFn)

		// replace kid with cloned thisKid
		n.InsertChild(addr, thisNode)

		switch {
		case otherIsNode:
			return thisNode.UnionRecPersist(cloneFn, otherNode, depth+1)
		case otherIsLeaf:
			if thisNode.InsertPersist(cloneFn, otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
				return 1
			}
			return 0
		case otherIsFringe:
			if thisNode.InsertPrefix(1, cloneFn(otherFringe.Value)) {
				return 1
			}
			return 0
		default:
			panic("logic error, wrong node type")
		}
	}

	// Case 3: All remaining cases need a new node
	// (thisChild is leaf or fringe, and we didn't hit the special cases above)

	nc := new(FastNode[V])

	// Push existing child down into new node
	switch {
	case thisIsLeaf:
		nc.Insert(thisLeaf.Prefix, thisLeaf.Value, depth+1)
	case thisIsFringe:
		nc.InsertPrefix(1, thisFringe.Value)
	default:
		panic("logic error, unexpected this child type")
	}

	// Replace child with new node
	n.InsertChild(addr, nc)

	// Now handle other child
	switch {
	case otherIsNode:
		return nc.UnionRec(cloneFn, otherNode, depth+1)
	case otherIsLeaf:
		if nc.Insert(otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
			return 1
		}
		return 0
	case otherIsFringe:
		if nc.InsertPrefix(1, cloneFn(otherFringe.Value)) {
			return 1
		}
		return 0
	default:
		panic("logic error, wrong other node type")
	}
}

// AllRec recursively traverses the trie starting at the current node,
// applying the provided yield function to every stored prefix and value.
//
// For each route entry (prefix and value), yield is invoked. If yield returns false,
// the traversal stops immediately, and false is propagated upwards,
// enabling early termination.
//
// The function handles all prefix entries in the current node, as well as any children -
// including sub-nodes, leaf nodes with full prefixes, and fringe nodes
// representing path-compressed prefixes. IP prefix reconstruction is performed on-the-fly
// from the current path and depth.
//
// The traversal order is not defined. This implementation favors simplicity
// and runtime efficiency over consistency of iteration sequence.
func (n *FastNode[V]) AllRec(path StridePath, depth int, is4 bool, yield func(netip.Prefix, V) bool) bool {
	var buf [256]uint8
	for _, idx := range n.Prefixes.AsSlice(&buf) {
		cidr := CidrFromPath(path, depth, is4, idx)
		val := n.MustGetPrefix(idx)

		// callback for this prefix and val
		if !yield(cidr, val) {
			// early exit
			return false
		}
	}

	// for all children (nodes and leaves) in this node do ...
	for _, addr := range n.Children.AsSlice(&buf) {
		anyKid := n.MustGetChild(addr)
		switch kid := anyKid.(type) {
		case *FastNode[V]:
			// rec-descent with this node
			path[depth] = addr
			if !kid.AllRec(path, depth+1, is4, yield) {
				// early exit
				return false
			}
		case *LeafNode[V]:
			// callback for this leaf
			if !yield(kid.Prefix, kid.Value) {
				// early exit
				return false
			}
		case *FringeNode[V]:
			fringePfx := CidrForFringe(path[:], depth, is4, addr)
			// callback for this fringe
			if !yield(fringePfx, kid.Value) {
				// early exit
				return false
			}

		default:
			panic("logic error, wrong node type")
		}
	}

	return true
}

// AllRecSorted recursively traverses the trie in prefix-sorted order and applies
// the given yield function to each stored prefix and value.
//
// Unlike AllRec, this implementation ensures that route entries are visited in
// canonical prefix sort order. To achieve this,
// both the prefixes and children of the current node are gathered, sorted,
// and then interleaved during traversal based on logical octet positioning.
//
// The function first sorts relevant entries by their prefix index and address value,
// using a comparison function that ranks prefixes according to their mask length and position.
// Then it walks the trie, always yielding child entries that fall before the current prefix,
// followed by the prefix itself. Remaining children are processed once all prefixes have been visited.
//
// Prefixes are reconstructed on-the-fly from the traversal path, and iteration includes all child types:
// inner nodes (recursive descent), leaf nodes, and fringe (compressed) prefixes.
//
// The order is stable and predictable, making the function suitable for use cases
// like table exports, comparisons or serialization.
//
// Parameters:
//   - path: the current traversal path through the trie
//   - depth: current depth in the trie (0-based)
//   - is4: true for IPv4 processing, false for IPv6
//   - yield: callback function invoked for each prefix/value pair
//
// Returns false if yield function requests early termination.
func (n *FastNode[V]) AllRecSorted(path StridePath, depth int, is4 bool, yield func(netip.Prefix, V) bool) bool {
	// get slice of all child octets, sorted by addr
	var childBuf [256]uint8
	allChildAddrs := n.Children.AsSlice(&childBuf)

	// get slice of all indexes, sorted by idx
	var idxBuf [256]uint8
	allIndices := n.Prefixes.AsSlice(&idxBuf)

	// sort indices in CIDR sort order
	slices.SortFunc(allIndices, CmpIndexRank)

	childCursor := 0

	// yield indices and children in CIDR sort order
	for _, pfxIdx := range allIndices {
		pfxOctet, _ := art.IdxToPfx(pfxIdx)

		// yield all children before idx
		for j := childCursor; j < len(allChildAddrs); j++ {
			childAddr := allChildAddrs[j]

			if childAddr >= pfxOctet {
				break
			}

			// yield the node (rec-descent) or leaf
			anyKid := n.MustGetChild(childAddr)
			switch kid := anyKid.(type) {
			case *FastNode[V]:
				path[depth] = childAddr
				if !kid.AllRecSorted(path, depth+1, is4, yield) {
					return false
				}
			case *LeafNode[V]:
				if !yield(kid.Prefix, kid.Value) {
					return false
				}
			case *FringeNode[V]:
				fringePfx := CidrForFringe(path[:], depth, is4, childAddr)
				// callback for this fringe
				if !yield(fringePfx, kid.Value) {
					// early exit
					return false
				}

			default:
				panic("logic error, wrong node type")
			}

			childCursor++
		}

		// yield the prefix for this idx
		cidr := CidrFromPath(path, depth, is4, pfxIdx)
		// n.prefixes.Items[i] not possible after sorting allIndices
		if !yield(cidr, n.MustGetPrefix(pfxIdx)) {
			return false
		}
	}

	// yield the rest of leaves and nodes (rec-descent)
	for j := childCursor; j < len(allChildAddrs); j++ {
		addr := allChildAddrs[j]
		anyKid := n.MustGetChild(addr)
		switch kid := anyKid.(type) {
		case *FastNode[V]:
			path[depth] = addr
			if !kid.AllRecSorted(path, depth+1, is4, yield) {
				return false
			}
		case *LeafNode[V]:
			if !yield(kid.Prefix, kid.Value) {
				return false
			}
		case *FringeNode[V]:
			fringePfx := CidrForFringe(path[:], depth, is4, addr)
			// callback for this fringe
			if !yield(fringePfx, kid.Value) {
				// early exit
				return false
			}

		default:
			panic("logic error, wrong node type")
		}
	}

	return true
}

// EachLookupPrefix performs a hierarchical lookup of all matching prefixes
// in the current node’s 8-bit stride-based prefix table.
//
// The function walks up the trie-internal complete binary tree (CBT),
// testing each possible prefix length mask (in decreasing order of specificity),
// and invokes the yield function for every matching entry.
//
// The given idx refers to the position for this stride's prefix and is used
// to derive a backtracking path through the CBT by repeatedly halving the index.
// At each step, if a prefix exists in the table, its corresponding CIDR is
// reconstructed and yielded. If yield returns false, traversal stops early.
//
// This function is intended for internal use during supernet traversal and
// does not descend the trie further.
func (n *FastNode[V]) EachLookupPrefix(ip netip.Addr, depth int, pfxIdx uint8, yield func(netip.Prefix, V) bool) (ok bool) {
	for ; pfxIdx > 0; pfxIdx >>= 1 {
		if n.Prefixes.Test(pfxIdx) {
			val := n.MustGetPrefix(pfxIdx)

			// get the CIDR back
			_, pfxLen := art.IdxToPfx(pfxIdx)
			cidr, _ := ip.Prefix(depth<<3 + int(pfxLen))

			if !yield(cidr, val) {
				return false
			}
		}
	}

	return true
}

// EachSubnet yields all prefix entries and child nodes covered by a given parent prefix,
// sorted in natural CIDR order, within the current node.
//
// The function iterates through all prefixes and children from the node’s stride tables.
// Only entries that fall within the address range defined by the parent prefix index (pfxIdx)
// are included. Matching entries are buffered, sorted, and passed through to the yield function.
//
// Child entries (nodes, leaves, fringes) that fall under the covered address range
// are processed recursively via AllRecSorted to ensure sorted traversal.
//
// This function is intended for internal use by Subnets(), and it assumes the
// current node is positioned at the point in the trie corresponding to the parent prefix.
func (n *FastNode[V]) EachSubnet(octets []byte, depth int, is4 bool, pfxIdx uint8, yield func(netip.Prefix, V) bool) bool {
	// octets as array, needed below more than once
	var path StridePath
	copy(path[:], octets)

	pfxFirstAddr, pfxLastAddr := art.IdxToRange(pfxIdx)

	allCoveredIndices := make([]uint8, 0, n.PrefixCount())

	var buf [256]uint8
	for _, idx := range n.Prefixes.AsSlice(&buf) {
		thisFirstAddr, thisLastAddr := art.IdxToRange(idx)

		if thisFirstAddr >= pfxFirstAddr && thisLastAddr <= pfxLastAddr {
			allCoveredIndices = append(allCoveredIndices, idx)
		}
	}

	// sort indices in CIDR sort order
	slices.SortFunc(allCoveredIndices, CmpIndexRank)

	// 2. collect all covered child addrs by prefix

	allCoveredChildAddrs := make([]uint8, 0, n.ChildCount())
	for _, addr := range n.Children.AsSlice(&buf) {
		if addr >= pfxFirstAddr && addr <= pfxLastAddr {
			allCoveredChildAddrs = append(allCoveredChildAddrs, addr)
		}
	}

	// 3. yield covered indices, path-compressed prefixes
	//    and children in CIDR sort order

	addrCursor := 0

	// yield indices and children in CIDR sort order
	for _, pfxIdx := range allCoveredIndices {
		pfxOctet, _ := art.IdxToPfx(pfxIdx)

		// yield all children before idx
		for j := addrCursor; j < len(allCoveredChildAddrs); j++ {
			addr := allCoveredChildAddrs[j]
			if addr >= pfxOctet {
				break
			}

			// yield the node or leaf?
			switch kid := n.MustGetChild(addr).(type) {
			case *FastNode[V]:
				path[depth] = addr
				if !kid.AllRecSorted(path, depth+1, is4, yield) {
					return false
				}

			case *LeafNode[V]:
				if !yield(kid.Prefix, kid.Value) {
					return false
				}

			case *FringeNode[V]:
				fringePfx := CidrForFringe(path[:], depth, is4, addr)
				// callback for this fringe
				if !yield(fringePfx, kid.Value) {
					// early exit
					return false
				}

			default:
				panic("logic error, wrong node type")
			}

			addrCursor++
		}

		// yield the prefix for this idx
		cidr := CidrFromPath(path, depth, is4, pfxIdx)
		// n.prefixes.Items[i] not possible after sorting allIndices
		if !yield(cidr, n.MustGetPrefix(pfxIdx)) {
			return false
		}
	}

	// yield the rest of leaves and nodes (rec-descent)
	for _, addr := range allCoveredChildAddrs[addrCursor:] {
		// yield the node or leaf?
		switch kid := n.MustGetChild(addr).(type) {
		case *FastNode[V]:
			path[depth] = addr
			if !kid.AllRecSorted(path, depth+1, is4, yield) {
				return false
			}
		case *LeafNode[V]:
			if !yield(kid.Prefix, kid.Value) {
				return false
			}
		case *FringeNode[V]:
			fringePfx := CidrForFringe(path[:], depth, is4, addr)
			// callback for this fringe
			if !yield(fringePfx, kid.Value) {
				// early exit
				return false
			}

		default:
			panic("logic error, wrong node type")
		}
	}

	return true
}

// Supernets yields all supernet prefixes of pfx that exist in the trie,
// in reverse order (most-specific first, least-specific last).
//
// It traverses upward from the given prefix toward the root, collecting
// matching prefixes along the path. The traversal uses a stack to yield
// results in reverse order, so that more-specific supernets appear before
// less-specific ones.
//
// The function handles all node types (internal nodes, leaves, and fringes)
// and stops early if the yield callback returns false.
//
// Parameters:
//   - pfx: The prefix for which to find supernets
//   - yield: Callback function invoked for each supernet prefix/value pair
//
// The yield function receives prefix/value pairs and returns false to stop
// the iteration early.
func (n *FastNode[V]) Supernets(pfx netip.Prefix, yield func(netip.Prefix, V) bool) {
	ip := pfx.Addr()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// stack of the traversed nodes for reverse ordering of supernets
	stack := [MaxTreeDepth]*FastNode[V]{}

	// run variable, used after for loop
	var depth int
	var octet byte

	// find last node along this octet path
LOOP:
	for depth, octet = range octets {
		// stepped one past the last stride of interest; back up to last and exit
		if depth > lastOctetPlusOne {
			depth--
			break
		}
		// push current node on stack
		stack[depth] = n

		// descend down the trie
		if !n.Children.Test(octet) {
			break LOOP
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *FastNode[V]:
			n = kid
			continue LOOP // descend down to next trie level

		case *LeafNode[V]:
			if kid.Prefix.Bits() > pfx.Bits() {
				break LOOP
			}

			if kid.Prefix.Overlaps(pfx) {
				if !yield(kid.Prefix, kid.Value) {
					// early exit
					return
				}
			}
			// end of trie along this octets path
			break LOOP

		case *FringeNode[V]:
			fringePfx := CidrForFringe(octets, depth, is4, octet)
			if fringePfx.Bits() > pfx.Bits() {
				break LOOP
			}

			if fringePfx.Overlaps(pfx) {
				if !yield(fringePfx, kid.Value) {
					// early exit
					return
				}
			}
			// end of trie along this octets path
			break LOOP

		default:
			panic("logic error, wrong node type")
		}
	}

	// start backtracking, unwind the stack
	for ; depth >= 0; depth-- {
		n = stack[depth]

		// only the lastOctet may have a different prefix len
		// all others are just host routes
		var idx uint8
		octet = octets[depth]
		// Last “octet” from prefix, update/insert prefix into node.
		// Note: For /32 and /128, depth never reaches lastOctetPlusOne (4/16),
		// so those are handled below via the fringe/leaf path.
		if depth == lastOctetPlusOne {
			idx = art.PfxToIdx(octet, lastBits)
		} else {
			idx = art.OctetToIdx(octet)
		}

		// micro benchmarking, skip if there is no match
		if !n.Contains(idx) {
			continue
		}

		// yield all the matching prefixes, not just the lpm
		if !n.EachLookupPrefix(ip, depth, idx, yield) {
			// early exit
			return
		}
	}
}

// Subnets yields all subnet prefixes covered by pfx that exist in the trie,
// in CIDR sort order.
//
// It first locates the trie node corresponding to pfx, then recursively
// yields all prefixes and child entries contained within that subtree.
// The traversal uses sorted iteration to maintain canonical CIDR ordering.
//
// The function handles various node types (internal nodes, leaves, and fringes)
// and uses EachSubnet and AllRecSorted for sorted traversal of covered prefixes.
//
// Parameters:
//   - pfx: The parent prefix whose subnets should be yielded
//   - yield: Callback function invoked for each subnet prefix/value pair
//
// The yield function receives prefix/value pairs and returns false to stop
// the iteration early. If pfx doesn't exist in the trie, no prefixes are yielded.
func (n *FastNode[V]) Subnets(pfx netip.Prefix, yield func(netip.Prefix, V) bool) {
	// values derived from pfx
	ip := pfx.Addr()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	// find the trie node
	for depth, octet := range octets {
		// Last “octet” from prefix, update/insert prefix into node.
		// Note: For /32 and /128, depth never reaches lastOctetPlusOne (4/16),
		// so those are handled below via the fringe/leaf path.
		if depth == lastOctetPlusOne {
			idx := art.PfxToIdx(octet, lastBits)
			n.EachSubnet(octets, depth, is4, idx, yield)
			return
		}

		if !n.Children.Test(octet) {
			return
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *FastNode[V]:
			n = kid
			continue // descend down to next trie level

		case *LeafNode[V]:
			if pfx.Bits() <= kid.Prefix.Bits() && pfx.Overlaps(kid.Prefix) {
				yield(kid.Prefix, kid.Value)
			}
			return // immediate return

		case *FringeNode[V]:
			// get the LPM prefix back from ip and depth
			// it's a fringe, bits are always /8, /16, /24, ...
			fringePfx, _ := ip.Prefix((depth + 1) << 3)

			if pfx.Bits() <= fringePfx.Bits() && pfx.Overlaps(fringePfx) {
				yield(fringePfx, kid.Value)
			}
			return // immediate return

		default:
			panic("logic error, wrong node type")
		}
	}
}

// Overlaps recursively compares two trie nodes and returns true
// if any of their prefixes or descendants overlap.
//
// The implementation checks for:
// 1. Direct overlapping prefixes on this node level
// 2. Prefixes in one node overlapping with children in the other
// 3. Matching child addresses in both nodes, which are recursively compared
//
// All 12 possible type combinations for child entries (node, leaf, fringe) are supported.
//
// The function is optimized for early exit on first match and uses heuristics to
// choose between set-based and loop-based matching for performance.
func (n *FastNode[V]) Overlaps(o *FastNode[V], depth int) bool {
	nPfxCount := n.PrefixCount()
	oPfxCount := o.PrefixCount()

	nChildCount := n.ChildCount()
	oChildCount := o.ChildCount()

	// ##############################
	// 1. Test if any routes overlaps
	// ##############################

	// full cross check
	if nPfxCount > 0 && oPfxCount > 0 {
		if n.OverlapsRoutes(o) {
			return true
		}
	}

	// ####################################
	// 2. Test if routes overlaps any child
	// ####################################

	// swap nodes to help chance on its way,
	// if the first call to expensive overlapsChildrenIn() is already true,
	// if both orders are false it doesn't help either
	if nChildCount > oChildCount {
		n, o = o, n

		nPfxCount = n.PrefixCount()
		oPfxCount = o.PrefixCount()

		nChildCount = n.ChildCount()
		oChildCount = o.ChildCount()
	}

	if nPfxCount > 0 && oChildCount > 0 {
		if n.OverlapsChildrenIn(o) {
			return true
		}
	}

	// symmetric reverse
	if oPfxCount > 0 && nChildCount > 0 {
		if o.OverlapsChildrenIn(n) {
			return true
		}
	}

	// ############################################
	// 3. children with same octet in nodes n and o
	// ############################################

	// stop condition, n or o have no children
	if nChildCount == 0 || oChildCount == 0 {
		return false
	}

	// stop condition, no child with identical octet in n and o
	if !n.Children.Intersects(&o.Children.BitSet256) {
		return false
	}

	return n.OverlapsSameChildren(o, depth)
}

// OverlapsRoutes compares the prefix sets of two nodes (n and o).
//
// It first checks for direct bitset intersection (identical indices),
// then walks both prefix sets using lpmTest to detect if any
// of the n-prefixes is contained in o, or vice versa.
func (n *FastNode[V]) OverlapsRoutes(o *FastNode[V]) bool {
	// some prefixes are identical, trivial overlap
	if n.Prefixes.Intersects(&o.Prefixes.BitSet256) {
		return true
	}

	// get the lowest idx (biggest prefix)
	nFirstIdx, _ := n.Prefixes.FirstSet()
	oFirstIdx, _ := o.Prefixes.FirstSet()

	// start with other min value
	nIdx := oFirstIdx
	oIdx := nFirstIdx

	nOK := true
	oOK := true

	// zip, range over n and o together to help chance on its way
	for nOK || oOK {
		if nOK {
			// does any route in o overlap this prefix from n
			if nIdx, nOK = n.Prefixes.NextSet(nIdx); nOK {
				if o.Contains(nIdx) {
					return true
				}

				if nIdx == 255 {
					// stop, don't overflow uint8!
					nOK = false
				} else {
					nIdx++
				}
			}
		}

		if oOK {
			// does any route in n overlap this prefix from o
			if oIdx, oOK = o.Prefixes.NextSet(oIdx); oOK {
				if n.Contains(oIdx) {
					return true
				}

				if oIdx == 255 {
					// stop, don't overflow uint8!
					oOK = false
				} else {
					oIdx++
				}
			}
		}
	}

	return false
}

// OverlapsChildrenIn checks whether the prefixes in node n
// overlap with any children (by address range) in node o.
//
// Uses bitset intersection or manual iteration heuristically,
// depending on prefix and child count.
//
// Bitset-based matching uses precomputed coverage tables
// to avoid per-address looping. This is critical for high fan-out nodes.
func (n *FastNode[V]) OverlapsChildrenIn(o *FastNode[V]) bool {
	pfxCount := n.PrefixCount()
	childCount := o.ChildCount()

	// heuristic: 15 is the crossover point where bitset operations become
	// more efficient than iteration, determined by micro benchmarks on typical
	// routing table distributions
	const overlapsRangeCutoff = 15

	doRange := childCount < overlapsRangeCutoff || pfxCount > overlapsRangeCutoff

	// do range over, not so many children and maybe too many prefixes for other algo below
	var buf [256]uint8
	if doRange {
		for _, addr := range o.Children.AsSlice(&buf) {
			if n.Contains(art.OctetToIdx(addr)) {
				return true
			}
		}
		return false
	}

	// do bitset intersection, alloted route table with child octets
	// maybe too many children for range-over or not so many prefixes to
	// build the alloted routing table from them

	// use allot table with prefixes as bitsets, bitsets are precalculated.
	for _, idx := range n.Prefixes.AsSlice(&buf) {
		if o.Children.Intersects(&allot.FringeRoutesLookupTbl[idx]) {
			return true
		}
	}

	return false
}

// OverlapsSameChildren compares all matching child addresses (octets)
// between node n and node o recursively.
//
// For each shared address, the corresponding child nodes (of any type)
// are compared using FastNodeOverlapsTwoChildren, which handles all
// node/leaf/fringe combinations.
func (n *FastNode[V]) OverlapsSameChildren(o *FastNode[V], depth int) bool {
	// intersect the child bitsets from n with o
	commonChildren := n.Children.Intersection(&o.Children.BitSet256)

	for addr, ok := commonChildren.NextSet(0); ok; {
		nChild := n.MustGetChild(addr)
		oChild := o.MustGetChild(addr)

		if n.OverlapsTwoChildren(nChild, oChild, depth+1) {
			return true
		}

		if addr == 255 {
			break // Prevent uint8 overflow
		}

		addr, ok = commonChildren.NextSet(addr + 1)
	}
	return false
}

// OverlapsPrefixAtDepth returns true if any route in the subtree rooted at this node
// overlaps with the given pfx, starting the comparison at the specified depth.
//
// This function supports structural overlap detection even in compressed or sparse
// paths within the trie, including fringe and leaf nodes. Matching is directional:
// it returns true if a route fully covers pfx, or if pfx covers an existing route.
//
// At each step, it checks for visible prefixes and children that may intersect the
// target prefix via stride-based longest-prefix test. The walk terminates early as
// soon as a structural overlap is found.
//
// This function underlies the top-level OverlapsPrefix behavior and handles details of
// trie traversal across varying prefix lengths and compression levels.
func (n *FastNode[V]) OverlapsPrefixAtDepth(pfx netip.Prefix, depth int) bool {
	ip := pfx.Addr()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)

	for ; depth < len(octets); depth++ {
		if depth > lastOctetPlusOne {
			break
		}

		octet := octets[depth]

		// full octet path in node trie, check overlap with last prefix octet
		if depth == lastOctetPlusOne {
			return n.OverlapsIdx(art.PfxToIdx(octet, lastBits))
		}

		// test if any route overlaps prefix´ so far
		// no best match needed, forward tests without backtracking
		if n.PrefixCount() != 0 && n.Contains(art.OctetToIdx(octet)) {
			return true
		}

		if !n.Children.Test(octet) {
			return false
		}

		// next child, node or leaf
		switch kid := n.MustGetChild(octet).(type) {
		case *FastNode[V]:
			n = kid
			continue

		case *LeafNode[V]:
			return kid.Prefix.Overlaps(pfx)

		case *FringeNode[V]:
			return true

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable: " + pfx.String())
}

// OverlapsIdx returns true if the given prefix index overlaps with any entry in this node.
//
// The overlap detection considers three categories:
//
//  1. Whether any stored prefix in this node covers the requested prefix (LPM test)
//  2. Whether the requested prefix covers any stored route in the node
//  3. Whether the requested prefix overlaps with any fringe or child entry
//
// Internally, it leverages precomputed bitsets from the allotment model,
// using fast bitwise set intersections instead of explicit range comparisons.
// This enables high-performance overlap checks on a single stride level
// without descending further into the trie.
func (n *FastNode[V]) OverlapsIdx(idx uint8) bool {
	// 1. Test if any route in this node overlaps prefix?
	if n.Contains(idx) {
		return true
	}

	// 2. Test if prefix overlaps any route in this node
	if n.Prefixes.Intersects(&allot.PfxRoutesLookupTbl[idx]) {
		return true
	}

	// 3. Test if prefix overlaps any child in this node
	return n.Children.Intersects(&allot.FringeRoutesLookupTbl[idx])
}

// OverlapsTwoChildren handles all 3x3 combinations of
// node kinds (node, leaf, fringe).
//
//	3x3 possible different combinations for n and o
//
//	node, node    --> overlaps rec descent
//	node, leaf    --> overlapsPrefixAtDepth
//	node, fringe  --> true
//
//	leaf, node    --> overlapsPrefixAtDepth
//	leaf, leaf    --> netip.Prefix.Overlaps
//	leaf, fringe  --> true
//
//	fringe, node    --> true
//	fringe, leaf    --> true
//	fringe, fringe  --> true
func (n *FastNode[V]) OverlapsTwoChildren(nChild, oChild any, depth int) bool {
	// child type detection
	nNode, nIsNode := nChild.(*FastNode[V])
	nLeaf, nIsLeaf := nChild.(*LeafNode[V])
	_, nIsFringe := nChild.(*FringeNode[V])

	oNode, oIsNode := oChild.(*FastNode[V])
	oLeaf, oIsLeaf := oChild.(*LeafNode[V])
	_, oIsFringe := oChild.(*FringeNode[V])

	// Handle all 9 combinations with a single expression
	switch {
	// NODE cases
	case nIsNode && oIsNode:
		return nNode.Overlaps(oNode, depth)
	case nIsNode && oIsLeaf:
		return nNode.OverlapsPrefixAtDepth(oLeaf.Prefix, depth)
	case nIsNode && oIsFringe:
		return true

	// LEAF cases
	case nIsLeaf && oIsNode:
		return oNode.OverlapsPrefixAtDepth(nLeaf.Prefix, depth)
	case nIsLeaf && oIsLeaf:
		return oLeaf.Prefix.Overlaps(nLeaf.Prefix)
	case nIsLeaf && oIsFringe:
		return true

	// FRINGE cases
	case nIsFringe:
		return true // fringe overlaps with everything

	default:
		panic("logic error, wrong node type combination")
	}
}
