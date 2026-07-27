// Code generated from file "commonmethods_tmpl.go"; DO NOT EDIT.

// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package bart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/gaissmai/bart/internal/nodes"
	"github.com/gaissmai/bart/internal/value"
)

func (t *Table[V]) sizeUpdate(is4 bool, delta int) {
	if is4 {
		t.size4 += delta
		return
	}
	t.size6 += delta
}

// insert adds or updates a prefix-value pair in the routing table.
// If the prefix already exists, its value is updated; otherwise a new entry is created.
// Invalid prefixes are silently ignored.
//
// The prefix is automatically canonicalized using pfx.Masked() to ensure
// consistent behavior regardless of host bits in the input.
func (t *Table[V]) insert(pfx netip.Prefix, val V) {
	if !pfx.IsValid() {
		return
	}

	// canonicalize prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()
	n := t.rootNodeByVersion(is4)

	if exists := n.Insert(pfx, val, 0); exists {
		return
	}

	// true insert, update size
	t.sizeUpdate(is4, 1)
}

// insertPersist is similar to insert but the receiver isn't modified.
//
// All nodes touched during insert are cloned and a new Table is returned.
// This is not a full [Table.Clone], all untouched nodes are still referenced
// from both Tables.
//
// If the payload type V contains pointers or needs deep copying,
// implement:
//
//	func (v V) Clone() V
//
// The bart package detects this via structural typing and deep‑copies
// values during persistent ops.
//
// Due to cloning overhead this is significantly slower than insert,
// typically taking μsec instead of nsec.
func (t *Table[V]) insertPersist(pfx netip.Prefix, val V) *Table[V] {
	if !pfx.IsValid() {
		return t
	}

	// canonicalize prefix
	pfx = pfx.Masked()
	is4 := pfx.Addr().Is4()

	// share size counters; root nodes cloned selectively.
	pt := &Table[V]{
		size4: t.size4,
		size6: t.size6,
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	// Clone root node corresponding to the IP version, for copy-on-write.
	n := &pt.root4

	if is4 {
		pt.root4 = *t.root4.CloneFlat(cloneFn)
		pt.root6 = t.root6
	} else {
		pt.root4 = t.root4
		pt.root6 = *t.root6.CloneFlat(cloneFn)

		n = &pt.root6
	}

	if !n.InsertPersist(cloneFn, pfx, val, 0) {
		pt.sizeUpdate(is4, 1)
	}

	return pt
}

// Delete removes the exact prefix pfx from the table in-place.
//
// This is an exact-match operation (no LPM). If pfx exists, the entry is
// removed. If pfx does not exist or pfx is invalid, the table is left unchanged.
//
// The prefix is canonicalized (Masked) before lookup.
func (t *Table[V]) Delete(pfx netip.Prefix) {
	if !pfx.IsValid() {
		return
	}

	// canonicalize prefix
	pfx = pfx.Masked()
	is4 := pfx.Addr().Is4()

	n := t.rootNodeByVersion(is4)
	if exists := n.Delete(pfx); exists {
		t.sizeUpdate(is4, -1)
	}
}

// Get performs an exact-prefix lookup and returns whether the exact
// prefix exists. The prefix is canonicalized (Masked) before lookup.
//
// This is an exact-match operation (no LPM). The prefix must match exactly
// in both address and prefix length to be found. If pfx exists, the
// associated value (zero value for Lite) and found=true is returned.
// If pfx does not exist or pfx is invalid, the zero value for V and
// exists=false is returned.
//
// For longest-prefix-match (LPM) lookups, use Contains(ip), Lookup(ip),
// LookupPrefix(pfx) or LookupPrefixLPM(pfx) instead.
func (t *Table[V]) Get(pfx netip.Prefix) (val V, exists bool) {
	if !pfx.IsValid() {
		return val, exists
	}
	// canonicalize prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()
	n := t.rootNodeByVersion(is4)

	return n.Get(pfx)
}

// DeletePersist is similar to Delete but does not modify the receiver.
//
// It performs a copy-on-write delete operation, cloning all nodes touched during
// deletion and returning a new Table reflecting the change.
//
// If the prefix is invalid or doesn't exist, the original table is
// returned unchanged.
//
// If the payload type V contains pointers or requires deep copying,
// it must implement the Clone method for correct cloning.
//
// Due to cloning overhead this is significantly slower than Delete,
// typically taking μsec instead of nsec.
func (t *Table[V]) DeletePersist(pfx netip.Prefix) *Table[V] {
	if !pfx.IsValid() {
		return t
	}

	// canonicalize prefix
	pfx = pfx.Masked()
	is4 := pfx.Addr().Is4()

	// Preflight check: avoid cloning if prefix doesn't exist
	n := t.rootNodeByVersion(is4)
	if _, found := n.Get(pfx); !found {
		return t
	}

	// share size counters; root nodes cloned selectively.
	pt := &Table[V]{
		size4: t.size4,
		size6: t.size6,
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	// Clone root node corresponding to the IP version, for copy-on-write.
	if is4 {
		pt.root4 = *t.root4.CloneFlat(cloneFn)
		pt.root6 = t.root6
		n = &pt.root4
	} else {
		pt.root4 = t.root4
		pt.root6 = *t.root6.CloneFlat(cloneFn)
		n = &pt.root6
	}

	if exists := n.DeletePersist(cloneFn, pfx); exists {
		pt.sizeUpdate(is4, -1)
	}

	return pt
}

// ModifyPersist is similar to Modify but the receiver isn't modified and
// a new *Table is returned.
func (t *Table[V]) ModifyPersist(pfx netip.Prefix, cb func(_ V, ok bool) (_ V, del bool)) *Table[V] {
	if !pfx.IsValid() {
		return t
	}

	// make a cheap test in front of expensive operation
	oldVal, ok := t.Get(pfx)
	val := oldVal

	// to clone or not to clone ...
	cloneFn := value.CloneFnFactory[V]()
	if cloneFn != nil && ok {
		val = cloneFn(oldVal)
	}

	newVal, del := cb(val, ok)

	switch {
	case !ok && del: // no-op
		return t

	case !ok && !del: // insert
		return t.InsertPersist(pfx, newVal)

	case ok && !del: // update
		return t.InsertPersist(pfx, newVal)

	case ok && del: // delete
		return t.DeletePersist(pfx)
	}

	panic("unreachable")
}

// Supernets returns an iterator over all supernet routes that cover the given prefix pfx.
//
// The traversal searches both exact-length and shorter (less specific) prefixes that
// include pfx. Starting from the most specific position in the trie,
// it walks upward through parent nodes and yields any matching entries found at each level.
//
// The iteration order is reverse-CIDR: from longest prefix match (LPM) towards
// least-specific routes.
//
// This can be used to enumerate all covering supernet routes in routing-based
// policy engines, diagnostics tools, or fallback resolution logic.
//
// Example:
//
//	for supernet, val := range table.Supernets(netip.MustParsePrefix("192.0.2.128/25")) {
//	    fmt.Println("Covered by:", supernet, "->", val)
//	}
//
// The iteration can be stopped early by breaking from the range loop.
// Returns an empty iterator if the prefix is invalid.
func (t *Table[V]) Supernets(pfx netip.Prefix) iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		if !pfx.IsValid() {
			return
		}

		// canonicalize the prefix
		pfx = pfx.Masked()

		is4 := pfx.Addr().Is4()
		n := t.rootNodeByVersion(is4)

		n.Supernets(pfx, yield)
	}
}

// Subnets returns an iterator over all subnets of the given prefix
// in natural CIDR sort order. This includes prefixes of the same length
// (exact match) and longer (more specific) prefixes that are contained
// within the given prefix.
//
// Example:
//
//	for sub, val := range table.Subnets(netip.MustParsePrefix("10.0.0.0/8")) {
//	    fmt.Println("Covered:", sub, "->", val)
//	}
//
// The iteration can be stopped early by breaking from the range loop.
// Returns an empty iterator if the prefix is invalid.
func (t *Table[V]) Subnets(pfx netip.Prefix) iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		if !pfx.IsValid() {
			return
		}

		pfx = pfx.Masked()
		is4 := pfx.Addr().Is4()

		n := t.rootNodeByVersion(is4)
		n.Subnets(pfx, yield)
	}
}

// OverlapsPrefix reports whether any prefix in the routing table overlaps with
// the given prefix. Two prefixes overlap if they share any IP addresses.
//
// The check is bidirectional: it returns true if the input prefix is covered by an existing
// route, or if any stored route is itself contained within the input prefix.
//
// Internally, the function normalizes the prefix and descends the relevant trie branch,
// using stride-based logic to identify overlap without performing a full lookup.
//
// This is useful for containment tests, route validation, or policy checks using prefix
// semantics without retrieving exact matches.
func (t *Table[V]) OverlapsPrefix(pfx netip.Prefix) bool {
	if !pfx.IsValid() {
		return false
	}

	// canonicalize the prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()
	n := t.rootNodeByVersion(is4)

	return n.OverlapsPrefixAtDepth(pfx, 0)
}

// Overlaps reports whether any route in the receiver table overlaps
// with a route in the other table, in either direction.
//
// The overlap check is bidirectional: it returns true if any IP prefix
// in the receiver is covered by the other table, or vice versa.
// This includes partial overlaps, exact matches, and supernet/subnet relationships.
//
// Both IPv4 and IPv6 route trees are compared independently. If either
// tree has overlapping routes, the function returns true.
//
// This is useful for conflict detection, policy enforcement,
// or validating mutually exclusive routing domains.
func (t *Table[V]) Overlaps(o *Table[V]) bool {
	if o == nil {
		return false
	}
	return t.Overlaps4(o) || t.Overlaps6(o)
}

// Overlaps4 is like [Table.Overlaps] but for the v4 routing table only.
func (t *Table[V]) Overlaps4(o *Table[V]) bool {
	if o == nil || t.size4 == 0 || o.size4 == 0 {
		return false
	}
	return t.root4.Overlaps(&o.root4, 0)
}

// Overlaps6 is like [Table.Overlaps] but for the v6 routing table only.
func (t *Table[V]) Overlaps6(o *Table[V]) bool {
	if o == nil || t.size6 == 0 || o.size6 == 0 {
		return false
	}
	return t.root6.Overlaps(&o.root6, 0)
}

// Union merges another routing table into the receiver table, modifying it in-place.
//
// All prefixes and values from the other table (o) are inserted into the receiver.
// If a duplicate prefix exists in both tables, the value from o replaces the existing entry.
// This duplicate is shallow-copied by default, but if the value type V implements the
// Clone method, the value is deeply cloned before insertion. See also Table.Clone.
func (t *Table[V]) Union(o *Table[V]) {
	if o == nil || o == t || (o.size4 == 0 && o.size6 == 0) {
		return
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	dup4 := t.root4.UnionRec(cloneFn, &o.root4, 0)
	dup6 := t.root6.UnionRec(cloneFn, &o.root6, 0)

	t.size4 += o.size4 - dup4
	t.size6 += o.size6 - dup6
}

// UnionPersist is similar to [Union] but the receiver isn't modified.
//
// All nodes touched during union are cloned and a new *Table is returned.
// If o is nil or empty, no nodes are touched and the receiver may be
// returned unchanged.
func (t *Table[V]) UnionPersist(o *Table[V]) *Table[V] {
	if o == nil || o == t || (o.size4 == 0 && o.size6 == 0) {
		return t
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	// new Table with root nodes just copied.
	pt := &Table[V]{
		root4: t.root4,
		root6: t.root6,
		//
		size4: t.size4,
		size6: t.size6,
	}

	// only clone the root node if there is something to union
	if o.size4 != 0 {
		pt.root4 = *t.root4.CloneFlat(cloneFn)
	}
	if o.size6 != 0 {
		pt.root6 = *t.root6.CloneFlat(cloneFn)
	}

	dup4 := pt.root4.UnionRecPersist(cloneFn, &o.root4, 0)
	dup6 := pt.root6.UnionRecPersist(cloneFn, &o.root6, 0)

	pt.size4 += o.size4 - dup4
	pt.size6 += o.size6 - dup6

	return pt
}

// Equal checks whether two tables are structurally and semantically equal.
// It ensures both trees (IPv4-based and IPv6-based) have the same sizes and
// recursively compares their root nodes.
//
// Value comparisons use reflect.DeepEqual by default. To avoid the potentially
// expensive reflect.DeepEqual, the payload type V can provide custom equality
// by implementing the following method:
//
//	Equal(other V) bool
//
// Example:
//
//	type MyValue struct { ID int }
//	func (v MyValue) Equal(other MyValue) bool { return v.ID == other.ID }
//
// The bart package will automatically detect and use this method via Go's
// structural typing.
func (t *Table[V]) Equal(o *Table[V]) bool {
	if o == nil || t.size4 != o.size4 || t.size6 != o.size6 {
		return false
	}
	if o == t {
		return true
	}

	return t.root4.EqualRec(&o.root4) && t.root6.EqualRec(&o.root6)
}

// Clone returns a copy of the routing table.
// The payload of type V is shallow copied by default. To enable deep copying,
// implement the following method on your value type:
//
//	Clone() V
//
// Example:
//
//	type MyValue struct { Data []byte }
//	func (v MyValue) Clone() MyValue {
//	    return MyValue{Data: slices.Clone(v.Data)}
//	}
//
// The bart package will automatically detect and use this method via Go's
// structural typing.
func (t *Table[V]) Clone() *Table[V] {
	if t == nil {
		return nil
	}

	c := new(Table[V])

	cloneFn := value.CloneFnFactory[V]()

	c.root4 = *t.root4.CloneRec(cloneFn)
	c.root6 = *t.root6.CloneRec(cloneFn)

	c.size4 = t.size4
	c.size6 = t.size6

	return c
}

// Size returns the prefix count.
func (t *Table[V]) Size() int {
	return t.size4 + t.size6
}

// Size4 returns the IPv4 prefix count.
func (t *Table[V]) Size4() int {
	return t.size4
}

// Size6 returns the IPv6 prefix count.
func (t *Table[V]) Size6() int {
	return t.size6
}

// All returns an iterator over all prefix–value pairs in the table.
//
// The entries from both IPv4 and IPv6 subtries are yielded using an internal recursive traversal.
// The iteration order is unspecified and may vary between calls; for a stable order, use AllSorted.
//
// You can use All directly in a for-range loop without providing a yield function.
// The Go compiler automatically synthesizes the yield callback for you:
//
//	for prefix, value := range t.All() {
//	    fmt.Println(prefix, value)
//	}
//
// Under the hood, the loop body is passed as a yield function to the iterator.
// If you break or return from the loop, iteration stops early as expected.
//
// IMPORTANT: Modifying or deleting entries during iteration is not allowed,
// as this would interfere with the internal traversal and may corrupt or
// prematurely terminate the iteration. If mutation of the table during
// traversal is required use persistent table methods, e.g.
//
//	pt := t // shallow copy of t
//	for pfx, val := range t.All() {
//		if cond(pfx, val) {
//		  pt = pt.DeletePersist(pfx)
//	  }
//	}
func (t *Table[V]) All() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		_ = t.root4.AllRec(stridePath{}, 0, true, yield) && t.root6.AllRec(stridePath{}, 0, false, yield)
	}
}

// All4 is like [Table.All] but only for the v4 routing table.
func (t *Table[V]) All4() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		_ = t.root4.AllRec(stridePath{}, 0, true, yield)
	}
}

// All6 is like [Table.All] but only for the v6 routing table.
func (t *Table[V]) All6() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		_ = t.root6.AllRec(stridePath{}, 0, false, yield)
	}
}

// AllSorted returns an iterator over all prefix–value pairs in the table,
// ordered in canonical CIDR prefix sort order.
//
// This can be used directly with a for-range loop;
// the Go compiler provides the yield function implicitly:
//
//	for prefix, value := range t.AllSorted() {
//	    fmt.Println(prefix, value)
//	}
//
// The traversal is stable and predictable across calls.
// Iteration stops early if you break out of the loop.
//
// IMPORTANT: Deleting entries during iteration is not allowed,
// as this would interfere with the internal traversal and may corrupt or
// prematurely terminate the iteration. If mutation of the table during
// traversal is required use persistent table methods.
func (t *Table[V]) AllSorted() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		_ = t.root4.AllRecSorted(stridePath{}, 0, true, yield) &&
			t.root6.AllRecSorted(stridePath{}, 0, false, yield)
	}
}

// AllSorted4 is like [Table.AllSorted] but only for the v4 routing table.
func (t *Table[V]) AllSorted4() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		_ = t.root4.AllRecSorted(stridePath{}, 0, true, yield)
	}
}

// AllSorted6 is like [Table.AllSorted] but only for the v6 routing table.
func (t *Table[V]) AllSorted6() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if t == nil {
			return
		}
		_ = t.root6.AllRecSorted(stridePath{}, 0, false, yield)
	}
}

// Fprint writes a hierarchical tree diagram of the ordered CIDRs
// with default formatted payload V to w.
//
// The order from top to bottom is in ascending order of the prefix address
// and the subtree structure is determined by the CIDRs coverage.
//
//	▼
//	├─ 10.0.0.0/8 (V)
//	│  ├─ 10.0.0.0/24 (V)
//	│  └─ 10.0.1.0/24 (V)
//	├─ 127.0.0.0/8 (V)
//	│  └─ 127.0.0.1/32 (V)
//	├─ 169.254.0.0/16 (V)
//	├─ 172.16.0.0/12 (V)
//	└─ 192.168.0.0/16 (V)
//	   └─ 192.168.1.0/24 (V)
//	▼
//	└─ ::/0 (V)
//	   ├─ ::1/128 (V)
//	   ├─ 2000::/3 (V)
//	   │  └─ 2001:db8::/32 (V)
//	   └─ fe80::/10 (V)
func (t *Table[V]) Fprint(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("nil writer")
	}
	if t == nil {
		return nil
	}

	// v4
	if err := t.fprint(w, true); err != nil {
		return err
	}

	// v6
	if err := t.fprint(w, false); err != nil {
		return err
	}

	return nil
}

// fprint is the version dependent adapter to fprintRec.
func (t *Table[V]) fprint(w io.Writer, is4 bool) error {
	n := t.rootNodeByVersion(is4)
	if n.IsEmpty() {
		return nil
	}

	if _, err := fmt.Fprint(w, "▼\n"); err != nil {
		return err
	}

	startParent := nodes.TrieItem[V]{
		Node: nil,
		Idx:  0,
		Path: stridePath{},
		Is4:  is4,
	}

	return n.FprintRec(w, startParent, "")
}

// MarshalText implements the [encoding.TextMarshaler] interface,
// just a wrapper for [Table.Fprint].
func (t *Table[V]) MarshalText() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := t.Fprint(w); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// MarshalJSON dumps the table into two sorted lists: for ipv4 and ipv6.
// Every root and subnet is an array, not a map, because the order matters.
func (t *Table[V]) MarshalJSON() ([]byte, error) {
	if t == nil {
		return []byte("null"), nil
	}

	result := struct {
		Ipv4 []DumpListNode[V] `json:"ipv4,omitempty"`
		Ipv6 []DumpListNode[V] `json:"ipv6,omitempty"`
	}{
		Ipv4: t.DumpList4(),
		Ipv6: t.DumpList6(),
	}

	buf, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// DumpList4 dumps the ipv4 tree into a list of roots and their subnets.
// It can be used to analyze the tree or build the text or JSON serialization.
func (t *Table[V]) DumpList4() []DumpListNode[V] {
	if t == nil {
		return nil
	}
	return t.dumpListRec(&t.root4, 0, stridePath{}, 0, true)
}

// DumpList6 dumps the ipv6 tree into a list of roots and their subnets.
// It can be used to analyze the tree or build custom JSON representation.
func (t *Table[V]) DumpList6() []DumpListNode[V] {
	if t == nil {
		return nil
	}
	return t.dumpListRec(&t.root6, 0, stridePath{}, 0, false)
}

// dumpListRec, build the data structure rec-descent with the help of directItemsRec.
// anyNode is nodes.BartNode, nodes.FastNode or nodes.LiteNode
func (t *Table[V]) dumpListRec(anyNode any, parentIdx uint8, path stridePath, depth int, is4 bool) []DumpListNode[V] {
	// recursion stop condition
	if anyNode == nil {
		return nil
	}

	// the same method is generated for all table types, therefore
	// type assert to the smallest needed interface.
	// The panic on wrong type assertion is by intention, MUST NOT happen
	n := anyNode.(interface {
		DirectItemsRec(uint8, stridePath, int, bool) []nodes.TrieItem[V]
	})

	directItems := n.DirectItemsRec(parentIdx, path, depth, is4)

	// sort the items by prefix
	slices.SortFunc(directItems, func(a, b nodes.TrieItem[V]) int {
		return nodes.CmpPrefix(a.Cidr, b.Cidr)
	})

	dumpNodes := make([]DumpListNode[V], 0, len(directItems))

	for _, item := range directItems {
		dumpNodes = append(dumpNodes, DumpListNode[V]{
			CIDR:  item.Cidr,
			Value: item.Val,
			// build it rec-descent, item.Node is also from type any
			Subnets: t.dumpListRec(item.Node, item.Idx, item.Path, item.Depth, is4),
		})
	}

	return dumpNodes
}

// dumpString is just a wrapper for dump.
func (t *Table[V]) dumpString() string {
	w := new(strings.Builder)
	t.dump(w)

	return w.String()
}

// dump the table structure and all the nodes to w.
func (t *Table[V]) dump(w io.Writer) {
	if t == nil {
		return
	}

	if t.size4 > 0 {
		stats := t.root4.StatsRec()
		fmt.Fprintln(w)
		fmt.Fprintf(w, "### IPv4: size(%d), subnodes(%d), prefixes(%d), leaves(%d), fringes(%d)",
			t.size4, stats.SubNodes, stats.Prefixes, stats.Leaves, stats.Fringes)

		t.root4.DumpRec(w, stridePath{}, 0, true)
	}

	if t.size6 > 0 {
		stats := t.root6.StatsRec()
		fmt.Fprintln(w)
		fmt.Fprintf(w, "### IPv6: size(%d), subnodes(%d), prefixes(%d), leaves(%d), fringes(%d)",
			t.size6, stats.SubNodes, stats.Prefixes, stats.Leaves, stats.Fringes)

		t.root6.DumpRec(w, stridePath{}, 0, false)
	}
}
