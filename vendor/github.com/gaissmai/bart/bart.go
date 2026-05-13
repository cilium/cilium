// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package bart

import (
	"net/netip"
	"sync"

	"github.com/gaissmai/bart/internal/art"
	"github.com/gaissmai/bart/internal/lpm"
	"github.com/gaissmai/bart/internal/nodes"
)

// Table represents an IPv4 and IPv6 routing table with payload V.
//
// The zero value is ready to use.
//
// The Table is safe for concurrent reads, but concurrent reads and writes
// must be externally synchronized. Mutation via Insert/Delete requires locks,
// or alternatively, use ...Persist methods which return a modified copy
// without altering the original table (copy-on-write).
//
// A Table must not be copied by value; always pass by pointer.
//
// Performance note: Do not pass IPv4-in-IPv6 addresses (e.g., ::ffff:192.0.2.1)
// as input. The methods do not perform automatic unmapping to avoid unnecessary
// overhead for the common case where native addresses are used.
// Users should unmap IPv4-in-IPv6 addresses to their native IPv4 form
// (e.g., 192.0.2.1) before calling these methods.
type Table[V any] struct {
	// used by -copylocks checker from `go vet`.
	_ [0]sync.Mutex

	// the root nodes, implemented as popcount compressed multibit tries
	root4 nodes.BartNode[V]
	root6 nodes.BartNode[V]

	// the number of prefixes in the routing table
	size4 int
	size6 int
}

// rootNodeByVersion, root node getter for ip version.
func (t *Table[V]) rootNodeByVersion(is4 bool) *nodes.BartNode[V] {
	if is4 {
		return &t.root4
	}
	return &t.root6
}

// Insert adds or updates a prefix-value pair in the routing table.
// If the prefix already exists, its value is updated; otherwise a new entry is created.
// Invalid prefixes are silently ignored.
//
// The prefix is automatically canonicalized using pfx.Masked() to ensure
// consistent behavior regardless of host bits in the input.
func (t *Table[V]) Insert(pfx netip.Prefix, val V) {
	t.insert(pfx, val)
}

// InsertPersist is similar to Insert but the receiver isn't modified.
//
// All nodes touched during insert are cloned and a new Table is returned.
// This is not a full [Table.Clone], all untouched nodes are still referenced
// from both Tables.
//
// If the payload type V contains pointers or needs deep copying,
// it must implement the Clone method to support correct cloning.
//
// Due to cloning overhead this is significantly slower than Insert,
// typically taking μsec instead of nsec.
func (t *Table[V]) InsertPersist(pfx netip.Prefix, val V) *Table[V] {
	return t.insertPersist(pfx, val)
}

// Modify applies an insert, update, or delete operation for the value
// associated with the given prefix. The supplied callback decides the
// operation: it is called with the current value (or zero if not found)
// and a boolean indicating whether the prefix exists. The callback must
// return a new value and a delete flag: del == false inserts or updates,
// del == true deletes the entry if it exists (otherwise no-op).
//
// The callback is invoked at most once per call.
//
// The operation is determined by the callback function, which is called with:
//
//	val:   the current value (or zero value if not found)
//	found: true if the prefix currently exists, false otherwise
//
// The callback returns:
//
//	val: the new value to insert or update (ignored if del == true)
//	del: true to delete the entry, false to insert or update
//
// Summary of callback semantics:
//
//	| cb-input        | cb-return       | Ops    |
//	------------------------------------- --------
//	| (zero,   false) | (_,      true)  | no-op  |
//	| (zero,   false) | (newVal, false) | insert |
//	| (oldVal, true)  | (newVal, false) | update |
//	| (oldVal, true)  | (_,      true)  | delete |
//	------------------------------------- --------
func (t *Table[V]) Modify(pfx netip.Prefix, cb func(_ V, ok bool) (_ V, del bool)) {
	if !pfx.IsValid() {
		return
	}

	// canonicalize prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()

	n := t.rootNodeByVersion(is4)

	delta := n.Modify(pfx, cb)
	t.sizeUpdate(is4, delta)
}

// Contains reports whether any stored prefix covers the given IP address.
// Returns false for invalid IP addresses.
//
// This performs longest-prefix matching and returns true if any prefix
// in the routing table contains the IP address, regardless of the associated value.
//
// It does not return the value nor the prefix of the matching item,
// but as a test against an allow-/deny-list it's often sufficient
// and even few nanoseconds faster than [Table.Lookup].
func (t *Table[V]) Contains(ip netip.Addr) bool {
	// speed is top priority: no explicit test for ip.IsValid
	// if ip is invalid, AsSlice() returns nil, Contains returns false.
	is4 := ip.Is4()
	n := t.rootNodeByVersion(is4)

	for _, octet := range ip.AsSlice() {
		// for contains, any lpm match is good enough, no backtracking needed
		if n.PrefixCount() != 0 && n.Contains(art.OctetToIdx(octet)) {
			return true
		}

		// stop traversing?
		if !n.Children.Test(octet) {
			return false
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *nodes.BartNode[V]:
			n = kid // descend down to next trie level

		case *nodes.FringeNode[V]:
			// fringe is the default-route for all possible octets below
			return true

		case *nodes.LeafNode[V]:
			return kid.Prefix.Contains(ip)
		}
	}

	return false
}

// Lookup performs a longest prefix match (LPM) lookup for the given address.
// It finds the most specific (longest) prefix in the routing table that
// contains the given address and returns its associated value.
//
// This is the fundamental operation for IP routing decisions, finding the
// best matching route for a destination address.
//
// Returns the associated value and true if a matching prefix is found.
// Returns zero value and false if no prefix contains the address.
func (t *Table[V]) Lookup(ip netip.Addr) (val V, ok bool) {
	if !ip.IsValid() {
		return val, ok
	}

	is4 := ip.Is4()
	octets := ip.AsSlice()

	n := t.rootNodeByVersion(is4)

	// stack of the traversed nodes for fast backtracking, if needed
	stack := [nodes.MaxTreeDepth]*nodes.BartNode[V]{}

	// run variable, used after for loop
	var depth int
	var octet byte

LOOP:
	// find leaf node
	for depth, octet = range octets {
		depth = depth & nodes.DepthMask // BCE, Lookup must be fast

		// push current node on stack for fast backtracking
		stack[depth] = n

		// go down in tight loop to last octet
		if !n.Children.Test(octet) {
			// no more nodes below octet
			break LOOP
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *nodes.BartNode[V]:
			n = kid
			continue LOOP // descend down to next trie level

		case *nodes.FringeNode[V]:
			// fringe is the default-route for all possible nodes below
			return kid.Value, true

		case *nodes.LeafNode[V]:
			if kid.Prefix.Contains(ip) {
				return kid.Value, true
			}
			// reached a path compressed prefix, stop traversing
			break LOOP
		}
	}

	// start backtracking, unwind the stack, bounds check eliminated
	for ; depth >= 0; depth-- {
		depth = depth & nodes.DepthMask // BCE

		n = stack[depth]

		// longest prefix match, skip if node has no prefixes
		if n.PrefixCount() != 0 {
			idx := art.OctetToIdx(octets[depth])
			// lookupIdx() manually inlined
			if lpmIdx, ok2 := n.Prefixes.IntersectionTop(&lpm.LookupTbl[idx]); ok2 {
				return n.MustGetPrefix(lpmIdx), ok2
			}
		}
	}

	return val, ok
}

// LookupPrefix performs a longest prefix match lookup for any address within
// the given prefix. It finds the most specific routing table entry that would
// match any address in the provided prefix range.
//
// This is functionally identical to LookupPrefixLPM but returns only the
// associated value, not the matching prefix itself.
//
// Returns the value and true if a matching prefix is found.
// Returns zero value and false if no match exists.
func (t *Table[V]) LookupPrefix(pfx netip.Prefix) (val V, ok bool) {
	_, val, ok = t.lookupPrefixLPM(pfx, false)
	return val, ok
}

// LookupPrefixLPM performs a longest prefix match lookup for any address within
// the given prefix. It finds the most specific routing table entry that would
// match any address in the provided prefix range.
//
// This is functionally identical to LookupPrefix but additionally returns the
// matching prefix (lpmPfx) itself along with the value.
//
// This method is slower than LookupPrefix and should only be used if the
// matching lpm entry is also required for other reasons.
//
// Returns the matching prefix, its associated value, and true if found.
// Returns zero values and false if no match exists.
func (t *Table[V]) LookupPrefixLPM(pfx netip.Prefix) (lpmPfx netip.Prefix, val V, ok bool) {
	return t.lookupPrefixLPM(pfx, true)
}

func (t *Table[V]) lookupPrefixLPM(pfx netip.Prefix, withLPM bool) (lpmPfx netip.Prefix, val V, ok bool) {
	if !pfx.IsValid() {
		return lpmPfx, val, ok
	}

	// canonicalize the prefix
	pfx = pfx.Masked()

	ip := pfx.Addr()
	bits := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	lastOctetPlusOne, lastBits := nodes.LastOctetPlusOneAndLastBits(pfx)

	n := t.rootNodeByVersion(is4)

	// record path to leaf node
	stack := [nodes.MaxTreeDepth]*nodes.BartNode[V]{}

	var depth int
	var octet byte

LOOP:
	// find the last node on the octets path in the trie,
	for depth, octet = range octets {
		depth = depth & nodes.DepthMask // BCE

		// stepped one past the last stride of interest; back up to last and break
		if depth > lastOctetPlusOne {
			depth--
			break
		}
		// push current node on stack
		stack[depth] = n

		// go down in tight loop to leaf node
		if !n.Children.Test(octet) {
			break LOOP
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *nodes.BartNode[V]:
			n = kid
			continue LOOP // descend down to next trie level

		case *nodes.LeafNode[V]:
			// reached a path compressed prefix, stop traversing
			if kid.Prefix.Bits() > bits || !kid.Prefix.Contains(ip) {
				break LOOP
			}
			return kid.Prefix, kid.Value, true

		case *nodes.FringeNode[V]:
			// the bits of the fringe are defined by the depth
			// maybe the LPM isn't needed, saves some cycles
			fringeBits := (depth + 1) << 3
			if fringeBits > bits {
				break LOOP
			}

			// the LPM isn't needed, saves some cycles
			if !withLPM {
				return netip.Prefix{}, kid.Value, true
			}

			// get the LPM prefix back from ip and depth
			// it's a fringe, bits are always /8, /16, /24, ...
			fringePfx, _ := ip.Prefix((depth + 1) << 3)
			return fringePfx, kid.Value, true
		}
	}

	// start backtracking, unwind the stack
	for ; depth >= 0; depth-- {
		depth = depth & nodes.DepthMask // BCE

		n = stack[depth]

		// longest prefix match, skip if node has no prefixes
		if n.Prefixes.Len() == 0 {
			continue
		}

		// only the lastOctet may have a different prefix len
		// all others are just host routes
		var idx uint8
		octet = octets[depth]
		// Last “octet” from prefix, update/insert prefix into node.
		// Note: For /32 and /128, depth never reaches lastOctetPlusOne (4 or 16),
		// so those are handled below via the fringe/leaf path.
		if depth == lastOctetPlusOne {
			idx = art.PfxToIdx(octet, lastBits)
		} else {
			idx = art.OctetToIdx(octet)
		}

		// manually inlined: lookupIdx(idx)
		var topIdx uint8
		if topIdx, ok = n.Prefixes.IntersectionTop(&lpm.LookupTbl[idx]); ok {
			val = n.MustGetPrefix(topIdx)

			// called from LookupPrefix
			if !withLPM {
				return netip.Prefix{}, val, ok
			}

			// called from LookupPrefixLPM

			// get the bits from depth and top idx
			pfxBits := int(art.PfxBits(depth, topIdx))

			// calculate the lpmPfx from incoming ip and new mask
			// netip.Addr.Prefix canonicalizes. Invariant: art.PfxBits(depth, topIdx)
			// yields a valid mask (v4: 0..32, v6: 0..128), so error is impossible.
			lpmPfx, _ = ip.Prefix(pfxBits)
			return lpmPfx, val, ok
		}
	}

	return lpmPfx, val, ok
}
