// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"cmp"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gaissmai/bart/internal/art"
	"github.com/gaissmai/bart/internal/value"
)

// strideLen represents the byte stride length for the multibit trie.
// Each stride processes 8 bits (1 byte) at a time.
const strideLen = 8

// MaxItems defines the maximum number of prefixes or children that can be stored in a single node.
// This corresponds to 256 possible values for an 8-bit stride.
const MaxItems = 256

// MaxTreeDepth represents the maximum depth of the trie structure.
// For IPv6 addresses, this allows up to 16 bytes of depth.
const MaxTreeDepth = 16

// DepthMask is used for bounds check elimination (BCE) when accessing depth-indexed arrays.
const DepthMask = MaxTreeDepth - 1

// StridePath represents a path through the trie, with a maximum depth of 16 octets for IPv6.
type StridePath [MaxTreeDepth]uint8

// TrieItem, a node has no path information about its predecessors,
// we collect this during the recursive descent.
type TrieItem[V any] struct {
	// for traversing, Path/Depth/Idx is needed to get the CIDR back from the trie.
	Node  any // BartNode, FastNode, LiteNode
	Is4   bool
	Path  StridePath
	Depth int
	Idx   uint8

	// for printing
	Cidr netip.Prefix
	Val  V
}

// StatsT, only used for dump, tests and benchmarks
type StatsT struct {
	Prefixes int
	Children int
	SubNodes int
	Leaves   int
	Fringes  int
}

type nodeType byte

const (
	nullNode nodeType = iota // empty node
	fullNode                 // prefixes and children or path-compressed prefixes
	halfNode                 // no prefixes, only children and path-compressed prefixes
	pathNode                 // only children, no prefix nor path-compressed prefixes
	stopNode                 // no children, only prefixes or path-compressed prefixes
)

// String implements Stringer for nodeType.
func (nt nodeType) String() string {
	switch nt {
	case nullNode:
		return "NULL"
	case fullNode:
		return "FULL"
	case halfNode:
		return "HALF"
	case pathNode:
		return "PATH"
	case stopNode:
		return "STOP"
	default:
		return "unreachable"
	}
}

// addrFmt, different format strings for IPv4 and IPv6, decimal versus hex.
func addrFmt(addr byte, is4 bool) string {
	if is4 {
		return fmt.Sprintf("%d", addr)
	}

	return fmt.Sprintf("0x%02x", addr)
}

// ip stride path, different formats for IPv4 and IPv6, dotted decimal or hex.
//
//	127.0.0
//	2001:0d
func ipStridePath(path StridePath, depth int, is4 bool) string {
	buf := new(strings.Builder)

	if is4 {
		for i, b := range path[:depth] {
			if i != 0 {
				buf.WriteString(".")
			}

			buf.WriteString(strconv.Itoa(int(b)))
		}

		return buf.String()
	}

	for i, b := range path[:depth] {
		if i != 0 && i%2 == 0 {
			buf.WriteString(":")
		}

		fmt.Fprintf(buf, "%02x", b)
	}

	return buf.String()
}

// CmpPrefix, helper function, compare func for prefix sort,
// all cidrs are already normalized
func CmpPrefix(a, b netip.Prefix) int {
	if cmpAddr := a.Addr().Compare(b.Addr()); cmpAddr != 0 {
		return cmpAddr
	}

	return cmp.Compare(a.Bits(), b.Bits())
}

// LeafNode represents a path-compressed routing entry that stores both prefix and value.
// Leaf nodes are used when a prefix doesn't align with trie stride boundaries
// and needs to be stored as a compressed path to save memory.
type LeafNode[V any] struct {
	Value  V
	Prefix netip.Prefix
}

// NewLeafNode creates a new leaf node with the specified prefix and value.
func NewLeafNode[V any](pfx netip.Prefix, val V) *LeafNode[V] {
	return &LeafNode[V]{Prefix: pfx, Value: val}
}

// FringeNode represents a path-compressed routing entry that stores only a value.
// The prefix is implicitly defined by the node's position in the trie.
// Fringe nodes are used for prefixes that align exactly with stride boundaries
// (/8, /16, /24, etc.) to save memory by not storing redundant prefix information.
type FringeNode[V any] struct {
	Value V
}

// NewFringeNode creates a new fringe node with the specified value.
func NewFringeNode[V any](val V) *FringeNode[V] {
	return &FringeNode[V]{Value: val}
}

// IsFringe determines whether a prefix qualifies as a "fringe node" -
// that is, a special kind of path-compressed leaf inserted at the final
// possible trie level (depth == lastOctet).
//
// Both "leaves" and "fringes" are path-compressed terminal entries;
// the distinction lies in their position within the trie:
//
//   - A leaf is inserted at any intermediate level if no further stride
//     boundary matches (depth < lastOctet).
//
//   - A fringe is inserted at the last possible stride level
//     (depth == lastOctet) before a prefix would otherwise land
//     as a direct prefix (depth == lastOctet+1).
//
// Special property:
//   - A fringe acts as a default route for all downstream bit patterns
//     extending beyond its prefix.
//
// Examples:
//
//	e.g. prefix is addr/8, or addr/16, or ... addr/128
//	depth <  lastOctet :  a leaf, path-compressed
//	depth == lastOctet :  a fringe, path-compressed
//	depth == lastOctet+1: a prefix with octet/pfx == 0/0 => idx == 1, a strides default route
//
// Logic:
//   - A prefix qualifies as a fringe if:
//     depth == lastOctet && lastBits == 0
//     (i.e., aligned on stride boundary, /8, /16, ... /128 bits)
func IsFringe(depth int, pfx netip.Prefix) bool {
	lastOctetPlusOne, lastBits := LastOctetPlusOneAndLastBits(pfx)
	return depth == lastOctetPlusOne-1 && lastBits == 0
}

// cmpIndexRank, sort indexes in prefix sort order.
func CmpIndexRank(aIdx, bIdx uint8) int {
	// convert idx [1..255] to prefix
	aOctet, aBits := art.IdxToPfx(aIdx)
	bOctet, bBits := art.IdxToPfx(bIdx)

	// cmp the prefixes, first by address and then by bits
	if aOctet == bOctet {
		return cmp.Compare(aBits, bBits)
	}
	return cmp.Compare(aOctet, bOctet)
}

// CidrFromPath reconstructs a CIDR prefix from a stride path, depth, and index.
// The prefix is determined by the node's position in the trie and the base index
// from the ART algorithm's complete binary tree representation.
//
// Parameters:
//   - path: The stride path through the trie
//   - depth: Current depth in the trie
//   - is4: True for IPv4 processing, false for IPv6
//   - idx: The base index from the prefix table
//
// Returns the reconstructed netip.Prefix.
func CidrFromPath(path StridePath, depth int, is4 bool, idx uint8) netip.Prefix {
	depth = depth & DepthMask // BCE

	// retrieve the last octet and pfxLen
	octet, pfxLen := art.IdxToPfx(idx)

	// set byte in path at depth with last octet
	path[depth] = octet

	// canonicalize
	clear(path[depth+1:])

	// make ip addr from octets
	var ip netip.Addr
	if is4 {
		ip = netip.AddrFrom4([4]byte(path[:4]))
	} else {
		ip = netip.AddrFrom16(path)
	}

	// calc bits with pathLen and pfxLen
	bits := depth<<3 + int(pfxLen)

	// PrefixFrom does not allocate and does not mask off the host bits of ip.
	// With the clear(), the non-canonical bytes have already been removed.
	return netip.PrefixFrom(ip, bits)
}

// CidrForFringe reconstructs a CIDR prefix for a fringe node from the traversal path.
// Since fringe nodes don't store their prefix explicitly, it's derived entirely
// from the node's position in the trie.
//
// Parameters:
//   - octets: The path of octets leading to the fringe
//   - depth: Current depth in the trie
//   - is4: True for IPv4 processing, false for IPv6
//   - lastOctet: The final octet where the fringe is located
//
// Returns the reconstructed netip.Prefix for the fringe.
func CidrForFringe(octets []byte, depth int, is4 bool, lastOctet uint8) netip.Prefix {
	depth = depth & DepthMask // BCE

	var path StridePath
	copy(path[:], octets)
	path[depth] = lastOctet

	// canonicalize, fringe bit boundaries are always a multiple of a byte
	clear(path[depth+1:])

	// make ip addr from octets
	var ip netip.Addr
	if is4 {
		ip = netip.AddrFrom4([4]byte(path[:4]))
	} else {
		ip = netip.AddrFrom16(path)
	}

	// it's a fringe, bits are always /8, /16, /24, ...
	bits := (depth + 1) << 3

	// PrefixFrom does not allocate and does not mask off the host bits of ip.
	// With the clear(), the non-canonical bytes have already been removed.
	return netip.PrefixFrom(ip, bits)
}

// LastOctetPlusOneAndLastBits returns the count of full 8‑bit strides (bits/8)
// and the leftover bits in the final stride (bits%8) for pfx.
//
// lastOctetPlusOne is the count of full 8‑bit strides (bits/8).
// lastBits is the remaining bit count in the final stride (bits%8),
//
// ATTENTION: Split the IP prefixes at 8bit borders, count from 0.
//
//	/7, /15, /23, /31, ..., /127
//
//	BitPos: [0-7],[8-15],[16-23],[24-31],[32]
//	BitPos: [0-7],[8-15],[16-23],[24-31],[32-39],[40-47],[48-55],[56-63],...,[120-127],[128]
//
//	0.0.0.0/0      => lastOctetPlusOne:  0, lastBits: 0 (default route)
//	0.0.0.0/7      => lastOctetPlusOne:  0, lastBits: 7
//	0.0.0.0/8      => lastOctetPlusOne:  1, lastBits: 0 (possible fringe)
//	10.0.0.0/8     => lastOctetPlusOne:  1, lastBits: 0 (possible fringe)
//	10.0.0.0/22    => lastOctetPlusOne:  2, lastBits: 6
//	10.0.0.0/29    => lastOctetPlusOne:  3, lastBits: 5
//	10.0.0.0/32    => lastOctetPlusOne:  4, lastBits: 0 (possible fringe)
//
//	::/0           => lastOctetPlusOne:  0, lastBits: 0 (default route)
//	::1/128        => lastOctetPlusOne: 16, lastBits: 0 (possible fringe)
//	2001:db8::/42  => lastOctetPlusOne:  5, lastBits: 2
//	2001:db8::/56  => lastOctetPlusOne:  7, lastBits: 0 (possible fringe)
//
//	/32 and /128 prefixes are special, they never form a new node,
//	At the end of the trie (IPv4: depth 4, IPv6: depth 16) they are always
//	inserted as a path‑compressed fringe.
//
// We are not splitting at /8, /16, ..., because this would mean that the
// first node would have 512 prefixes, 9 bits from [0-8]. All remaining nodes
// would then only have 8 bits from [9-16], [17-24], [25..32], ...
// but the algorithm would then require a variable length bitset.
//
// If you can commit to a fixed size of [4]uint64, then the algorithm is
// much faster due to modern CPUs.
//
// Perhaps a future Go version that supports SIMD instructions for the [4]uint64 vectors
// will make the algorithm even faster on suitable hardware.
func LastOctetPlusOneAndLastBits(pfx netip.Prefix) (lastOctetPlusOne int, lastBits uint8) {
	// lastOctetPlusOne:  range from 0..4 or 0..16 !ATTENTION: not 0..3 or 0..15
	// lastBits:          range from 0..7
	bits := pfx.Bits()

	//nolint:gosec  // G115: narrowing conversion is safe here (bits in [0..128])
	return bits >> 3, uint8(bits & 7)
}

// CloneLeaf creates and returns a copy of the leafNode receiver.
// If cloneFn is nil, the value is copied directly without modification.
// Otherwise, cloneFn is applied to the value for deep cloning.
// The prefix field is always copied as is.
func (l *LeafNode[V]) CloneLeaf(cloneFn value.CloneFunc[V]) *LeafNode[V] {
	if l == nil {
		return nil
	}

	if cloneFn == nil {
		return &LeafNode[V]{Prefix: l.Prefix, Value: l.Value}
	}
	return &LeafNode[V]{Prefix: l.Prefix, Value: cloneFn(l.Value)}
}

// cloneFringe creates and returns a copy of the fringeNode receiver.
// If cloneFn is nil, the value is copied directly without modification.
// Otherwise, cloneFn is applied to the value for deep cloning.
func (l *FringeNode[V]) CloneFringe(cloneFn value.CloneFunc[V]) *FringeNode[V] {
	if l == nil {
		return nil
	}

	if cloneFn == nil {
		return &FringeNode[V]{Value: l.Value}
	}
	return &FringeNode[V]{Value: cloneFn(l.Value)}
}
